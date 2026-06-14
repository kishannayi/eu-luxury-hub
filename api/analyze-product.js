// EU Luxury Hub — AI Product Analyzer
// Vercel serverless function (runs on Vercel infrastructure, NOT in customer browser)
// Receives a product image, asks Claude AI to identify it, returns structured JSON.
//
// SETUP REQUIRED:
//   1. Get an Anthropic API key from https://console.anthropic.com
//   2. In Vercel project settings → Environment Variables, add:
//        Name:  ANTHROPIC_API_KEY
//        Value: <paste your key, starts with sk-ant-...>
//   3. Redeploy the project (Vercel does this automatically)
//
// Cost note: Each AI analysis costs ~$0.003 (less than 1 cent).
// 100 product uploads = ~30 cents.

export default async function handler(req, res) {
  // CORS (safe for same-origin Vercel deploys)
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }

  let body = req.body;
  // Vercel auto-parses JSON if Content-Type is right, but defensive parsing:
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
  }
  const image = body && body.image;
  if (!image) return res.status(400).json({ error: 'No image provided in request body' });

  // Parse data URL: data:image/jpeg;base64,XXXX
  const match = String(image).match(/^data:(image\/[a-z+]+);base64,(.+)$/i);
  if (!match) return res.status(400).json({ error: 'Image must be a base64 data URL (data:image/...;base64,...)' });
  const mediaType = match[1].toLowerCase();
  const base64Data = match[2];

  // Only allow common image types
  const allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
  if (!allowed.includes(mediaType)) {
    return res.status(400).json({ error: 'Unsupported image type: ' + mediaType });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      error: 'ANTHROPIC_API_KEY not configured. In Vercel: Settings → Environment Variables → add ANTHROPIC_API_KEY with your Anthropic API key, then redeploy.'
    });
  }

  const prompt = `You are a luxury product cataloger for an EU reseller boutique. Look at this product image and identify the item.

Respond ONLY with raw JSON in this exact schema, no markdown, no code fences, no commentary:

{
  "name": "Creative 2-4 word product name (luxe-sounding, NEVER use real trademarked brand names like Nike, Rolex, Gucci etc — invent a stylish name)",
  "brand": "Generic category-style label: one of 'Sneakers', 'Timepieces', 'Apparel', 'Denim', 'Fine Jewellery', 'Bags', 'Accessories', 'Headwear'",
  "cat": "EXACTLY one of: sneaker, watch, hoodie, denim, jewel, tee, bag, cap",
  "g": "men or women (best guess from styling)",
  "sizes": ["array of typical sizes. Sneakers: EU sizes like 40,41,42,43,44 or 36,37,38,39,40 for women. Hoodie/Tee: S,M,L,XL. Denim: 30,32,34,36. Watch/Jewel/Bag/Cap: One Size"],
  "colors": ["main visible colours, max 3, use simple names: Black,White,Cream,Beige,Tan,Brown,Sand,Mocha,Charcoal,Grey,Navy,Blue,Indigo,Red,Pink,Blush,Olive,Sage,Green,Gold,Silver,Rose Gold,Graphite"],
  "tag": "NEW or HOT or SALE or empty string"
}

If the image is not a product (e.g. blurry, person's face, random), respond with: {"error":"Not a clear product image"}`;

  try {
    const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-5',
        max_tokens: 800,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64Data } },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    const aiData = await aiResp.json();

    if (!aiResp.ok) {
      // Surface Anthropic-specific error message
      const msg = (aiData && aiData.error && aiData.error.message) || `Anthropic API error (HTTP ${aiResp.status})`;
      return res.status(500).json({ error: msg });
    }

    let text = '';
    if (aiData && Array.isArray(aiData.content)) {
      const textBlock = aiData.content.find(c => c.type === 'text');
      if (textBlock) text = textBlock.text || '';
    }
    text = text.trim();
    // Strip code fences just in case the model adds them
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();

    let parsed;
    try { parsed = JSON.parse(text); }
    catch (e) {
      return res.status(500).json({ error: 'AI returned invalid JSON: ' + text.slice(0, 200) });
    }

    if (parsed.error) {
      return res.status(422).json({ error: parsed.error });
    }

    // Sanity defaults
    parsed.name = parsed.name || 'Untitled Piece';
    parsed.brand = parsed.brand || 'Atelier';
    parsed.cat = parsed.cat || 'sneaker';
    parsed.g = (parsed.g === 'women') ? 'women' : 'men';
    parsed.sizes = Array.isArray(parsed.sizes) ? parsed.sizes : ['One Size'];
    parsed.colors = Array.isArray(parsed.colors) ? parsed.colors : ['Black'];
    parsed.tag = parsed.tag || '';

    return res.status(200).json(parsed);
  } catch (e) {
    return res.status(500).json({ error: 'Server error: ' + (e.message || String(e)) });
  }
}
