// Catch-all 404. vercel.json rewrites any path that isn't a known static asset
// (index.html / style.css / app.js) or a known API route here, so junk and
// scanner traffic gets a clean JSON 404 at the edge instead of probing the
// static error page or revealing anything about routing.

const { send } = require('./_lib');

module.exports = function handler(req, res) {
  return send(res, 404, { error: 'not_found' });
};
