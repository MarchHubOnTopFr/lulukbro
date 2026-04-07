let ready = false;

function checkServerReady(req, res, next) {
  if (!ready) {
    return res.status(503).json({ success: false, message: 'Server is warming up, please try again shortly.' });
  }
  next();
}

function setServerReady(value) {
  ready = value;
}

function isServerReady() {
  return ready;
}

module.exports = { checkServerReady, setServerReady, isServerReady };
