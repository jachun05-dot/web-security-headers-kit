// Express with a fresh nonce on every request and 'strict-dynamic'.
// npm install express, then: node examples/express-nonce.js
import express from 'express';
import { securityHeaders } from 'web-security-headers-kit/express';

const app = express();
app.use(securityHeaders({ services: ['google-analytics'], strictDynamic: true, reportUri: '/csp-report' }));

app.get('/', (req, res) => {
  const n = res.locals.cspNonce;
  res.send(`<!doctype html><title>Hi</title>
<script nonce="${n}" src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
<script nonce="${n}">window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);} gtag('js', new Date()); gtag('config', 'G-XXXX');</script>
<h1>Only scripts with this request's nonce can run.</h1>`);
});

app.listen(3000, () => console.log('http://localhost:3000'));
