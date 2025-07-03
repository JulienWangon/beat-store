module.exports = {
  preset: '@shelf/jest-mongodb',  // utilise mongodb-memory-server
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.js'],  // place tes tests sous __tests__/
  verbose: true
};
