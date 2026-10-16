<?php

// TrustedHostingPlatforms lists well-known legitimate static/app hosting services
// whose subdomains appear in the PSL private section (returning icann=false from
// publicsuffix.PublicSuffix). These are operated by reputable companies and must
// not be penalized as "unregulated" TLDs. Subdomains on these platforms also
// lack per-subdomain NS records (the platform manages the whole zone) and are
// inherently unranked, so rank-0 and missing-NS penalties are suppressed too.
return [
   'github.io' => true, // GitHub Pages
   'github.dev' => true, // GitHub dev environments
   'gitlab.io' => true, // GitLab Pages
   'netlify.app' => true, // Netlify
   'vercel.app' => true, // Vercel
   'pages.dev' => true, // Cloudflare Pages
   'workers.dev' => true, // Cloudflare Workers
   'web.app' => true, // Firebase Hosting
   'firebaseapp.com'=> true, // Firebase Hosting (legacy)
   'surge.sh' => true, // Surge.sh
   'fly.dev' => true, // Fly.io
   'onrender.com' => true, // Render
   'herokuapp.com' => true, // Heroku
   'glitch.me' => true, // Glitch
   'replit.app' => true, // Replit
   'bitbucket.io' => true, // Bitbucket Pages
   'azurewebsites.net' => true, // Azure App Service
   'azurestaticapps.net' => true, // Azure Static Web Apps
   'amplifyapp.com' => true, // AWS Amplify
   'readthedocs.io' => true, // ReadTheDocs
   'huggingface.co' => true, // Hugging Face Spaces (has PSL entry)
   'streamlit.app' => true, // Streamlit Cloud
   'railway.app' => true, // Railway
   'koyeb.app' => true, // Koyeb
   'cyclic.app' => true, // Cyclic
   'deno.dev' => true, // Deno Deploy
   'val.run' => true, // Val Town

   // File and asset hosting run by large providers
   'googleapis.com' => true, // Google Cloud Storage (storage.googleapis.com)
   'appspot.com' => true, // Google App Engine
   'blogspot.com' => true, // Blogger
   'githubusercontent.com' => true, // GitHub raw files and release assets
   'amazonaws.com' => true, // Amazon S3 in every region, EC2 hostnames
   'core.windows.net' => true, // Azure Storage: blob., web. (static sites), file.
   'cloudfront.net' => true, // Amazon CloudFront
   'r2.dev' => true, // Cloudflare R2
   'digitaloceanspaces.com' => true, // DigitalOcean Spaces, per region
   'linodeobjects.com' => true, // Akamai (Linode) Object Storage, per region
];
