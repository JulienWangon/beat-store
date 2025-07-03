const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Définition du schéma Mongoose pour l'entité User
const userSchema = new mongoose.Schema({
  // Adresse email unique de l'utilisateur, format normalisé
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  // Pseudo unique choisi par l'utilisateur
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  // Mot de passe en clair hashé lors de la sauvegarde
  password: {
    type: String,
    required: true
  },
  // Rôle de l'utilisateur: contrôle l'accès aux parties admin
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  // Jeton et date d'expiration pour la réinitialisation du mot de passe
  passwordResetToken: {
    type: String,
    default: ''
  },
  passwordResetExpires: {
    type: Date
  }
}, {
  // Ajoute automatiquement createdAt et updatedAt
  timestamps: true
});

// === HOOKS === //
// Avant chaque 'save', si le password est modifié, on le hash avec bcrypt
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);              // Génération d'un sel
    this.password = await bcrypt.hash(this.password, salt); // Hash du mot de passe
    next();
  } catch (err) {
    next(err);
  }
});

// === MÉTHODES D'INSTANCE === //

// Vérifie qu'un mot de passe en clair correspond bien au hash stocké
userSchema.methods.verifyPassword = function(plainPassword) {
  return bcrypt.compare(plainPassword, this.password);
};

// Génère un JWT contenant l'id et le rôle de l'utilisateur
userSchema.methods.generateAuthToken = function() {
  const payload = { id: this._id, role: this.role };
  const secret = process.env.JWT_SECRET || 'changeme';
  // Token valable 7 jours
  return jwt.sign(payload, secret, { expiresIn: '7d' });
};

// Génère un jeton de reset (brut), stocke son hash et son expiration
userSchema.methods.generatePasswordReset = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');    // Jeton en clair
  this.passwordResetToken = crypto.createHash('sha256')         // On stocke uniquement le hash
    .update(resetToken)
    .digest('hex');
  this.passwordResetExpires = Date.now() + 3600000;              // Expiration dans 1h
  return resetToken;                                            // À envoyer par email
};

// Sérialise le document en JSON en retirant les champs sensibles
userSchema.methods.toJSON = function() {
  const obj = this.toObject();  
  delete obj.password;                // Retire le hash du mot de passe
  delete obj.__v;                     // Retire le champ de version Mongoose
  delete obj.passwordResetToken;      // Retire le hash de reset
  delete obj.passwordResetExpires;    // Retire la date d'expiration
  return obj;
};

// === MÉTHODES STATIQUES === //

// Authentifie par email et mot de passe
userSchema.statics.findByCredentials = async function(email, plainPassword) {
  const user = await this.findOne({ email });
  if (!user) throw new Error('Utilisateur non trouvé');
  const isValid = await bcrypt.compare(plainPassword, user.password);
  if (!isValid) throw new Error('Mot de passe incorrect');
  return user;
};

// Traite la réinitialisation : vérifie le token hashé et la date, met à jour le mot de passe
userSchema.statics.resetPassword = async function(email, token, newPassword) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await this.findOne({
    email,
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() } // Vérifie que le token n'a pas expiré
  });
  if (!user) {
    throw new Error('Token invalide ou expiré');
  }
  user.password = newPassword;          // Le hook 'pre' va hasher le nouveau mot de passe
  user.passwordResetToken = '';        // On efface les infos de reset
  user.passwordResetExpires = undefined;
  await user.save();
  return user;
};

// Export du modèle User
module.exports = mongoose.model('User', userSchema);
