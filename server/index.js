require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware pour parser le JSON
app.use(express.json());

// Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/beats_store', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('🔗 Connecté à MongoDB'))
.catch(err => console.error('❌ Erreur de connexion MongoDB', err));

// Route de test
app.get('/', (req, res) => {
  res.send('🚀 Backend up and running!');
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`📡 Server listening on http://localhost:${PORT}`);
});