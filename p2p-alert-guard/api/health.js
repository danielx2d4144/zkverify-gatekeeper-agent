const { handleHealth } = require('../src/http');
module.exports = (req, res) => handleHealth(req, res);
