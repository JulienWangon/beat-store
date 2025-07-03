// Import des modules nécessaires pour les tests
const mongoose = require('mongoose');                       // ODM pour MongoDB
const { MongoMemoryServer } = require('mongodb-memory-server'); // Serveur MongoDB in-memory pour isolation
const User = require('../models/User');                     // Modèle User à tester
const jwt = require('jsonwebtoken');                         // Pour vérifier la validité des JWT

let mongoServer;

// Avant tous les tests, démarrer une instance MongoDB in-memory
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create(); // Création du serveur en mémoire
  const uri = mongoServer.getUri();               // Récupère l'URI de connexion
  await mongoose.connect(uri, {                   // Connexion de Mongoose à cette base
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
});

// Après tous les tests, fermer la connexion et arrêter le serveur in-memory
afterAll(async () => {
  await mongoose.disconnect(); // Déconnexion de Mongoose
  await mongoServer.stop();    // Arrêt du serveur Mongo in-memory
});

// Après chaque test, vider la collection User pour garantir l'isolation
afterEach(async () => {
  await User.deleteMany();      // Suppression de tous les documents User
});

// Regroupement des tests relatifs au modèle User
describe('User model', () => {
  
  // Test 1 : hash et vérification du mot de passe
  it('should hash password on save and verifyPassword() should return true', async () => {
    const user = new User({ email: 'test@example.com', username: 'testuser', password: 'MyP@ssw0rd' });
    await user.save();

    expect(user.password).not.toBe('MyP@ssw0rd');
    const isValid = await user.verifyPassword('MyP@ssw0rd');
    expect(isValid).toBe(true);
  });

  // Test 2 : génération et validation du JWT
  it('generateAuthToken() should return a valid JWT containing id and role', async () => {
    const user = new User({ email: 'jane@doe.com', username: 'jane', password: 'Secret123' });
    await user.save();

    const token = user.generateAuthToken();
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'changeme');
    expect(decoded.id).toEqual(user._id.toString());
    expect(decoded.role).toEqual(user.role);
  });

  // Test 3 : workflow de réinitialisation du mot de passe
  it('generatePasswordReset() and resetPassword() should work correctly', async () => {
    const user = new User({ email: 'foo@bar.com', username: 'foobar', password: 'FooBar123' });
    await user.save();

    const resetToken = user.generatePasswordReset();
    await user.save();

    expect(user.passwordResetToken).toBeDefined();
    expect(user.passwordResetExpires).toBeDefined();

    const newPassword = 'NewP@ss456';
    const updated = await User.resetPassword('foo@bar.com', resetToken, newPassword);

    const valid = await updated.verifyPassword(newPassword);
    expect(valid).toBe(true);
    expect(updated.passwordResetToken).toBe('');
    expect(updated.passwordResetExpires).toBeUndefined();
  });

  // Test 4 : gestion des erreurs d'authentification
  it('findByCredentials() should throw for wrong email or password', async () => {
    const user = new User({ email: 'a@b.com', username: 'ab', password: 'Pass123' });
    await user.save();

    await expect(User.findByCredentials('no@user.com', 'Pass123')).rejects.toThrow('Utilisateur non trouvé');
    await expect(User.findByCredentials('a@b.com', 'WrongPass')).rejects.toThrow('Mot de passe incorrect');
  });

  // Test 5 : vérification de la méthode toJSON pour enlever les champs sensibles
  it('toJSON() should not include sensitive fields', async () => {
    const user = new User({ email: 'sensitive@fields.com', username: 'secure', password: 'Secure123' });
    await user.save();
    // Générer token de reset pour tester suppression
    user.generatePasswordReset();
    await user.save();

    const json = user.toJSON();
    expect(json.password).toBeUndefined();
    expect(json.__v).toBeUndefined();
    expect(json.passwordResetToken).toBeUndefined();
    expect(json.passwordResetExpires).toBeUndefined();
    // Les autres champs doivent exister
    expect(json.email).toBe('sensitive@fields.com');
    expect(json.username).toBe('secure');
  });

  // Test 6 : timestamps générés correctly
  it('should have createdAt and updatedAt timestamps after save', async () => {
    const user = new User({ email: 'time@stamp.com', username: 'timer', password: 'Time123' });
    await user.save();

    expect(user.createdAt).toBeInstanceOf(Date);
    expect(user.updatedAt).toBeInstanceOf(Date);
    expect(user.updatedAt.getTime()).toBeGreaterThanOrEqual(user.createdAt.getTime());
  });

  // Test 7 : ne pas re-hasher si le password n'est pas modifié
  it('should not re-hash password if not modified', async () => {
    const user = new User({ email: 'nochange@hash.com', username: 'nochange', password: 'NoChange123' });
    await user.save();
    const originalHash = user.password;

    user.username = 'updatedname';
    await user.save();
    expect(user.password).toBe(originalHash);
  });

});
