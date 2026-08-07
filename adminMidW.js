const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ greska: 'Pristup odbijen. Token nije proslijeđen.' });
    }

    try {
        const dekodiraniAdmin = jwt.verify(token, process.env.JWT_SECRET);

        req.user = dekodiraniAdmin;

        next();
    } catch (error) {
        res.status(401).json({ greska: 'JWT token je istekao ili je neispravan.' });
    }
};