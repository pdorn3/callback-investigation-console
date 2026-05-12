// src/server.js
require('dotenv').config();

const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Callback Investigation Console is running.');
});

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'callback-investigation-console'
  });
});

app.listen(PORT, () => {
  console.log(`Callback Investigation Console running on port ${PORT}`);
});