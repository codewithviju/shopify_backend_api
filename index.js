import express from "express";
import crypto from "crypto";
import axios from "axios";

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Step 1: Redirect to Shopify's OAuth screen
app.get("/auth", (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop parameter");

  const redirectUri = `${process.env.HOST}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${process.env.SHOPIFY_API_KEY}` +
    `&scope=read_products,write_products` + // adjust scopes as needed
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=nonce` + // should be a random string in production
    `&grant_options[]=per-user`;

  res.redirect(installUrl);
});

// Step 2: Handle callback, validate HMAC, exchange code for access token
app.get("/auth/callback", async (req, res) => {
  const { shop, hmac, code } = req.query;

  if (!shop || !hmac || !code) {
    return res.status(400).send("Required parameters missing");
  }

  // Validate HMAC
  const { hmac: _hmac, ...params } = req.query;
  const message = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("&");

  const generatedHash = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  if (generatedHash !== hmac) {
    return res.status(400).send("HMAC validation failed");
  }

  // Exchange code for access token
  try {
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code,
      }
    );

    const { access_token } = tokenResponse.data;
    // Save access_token securely for this shop

    res.send("App successfully installed! Access token: " + access_token);
    // Or redirect to your app's dashboard
  } catch (err) {
    res.status(500).send("Failed to get access token: " + err.message);
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

export default app;
