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
//ovo se komplet da zakomentirati, tablice za usera i admina su ionako odvojene, cisto PoC
        if (req.user.uloga !== 'admin') {
            return res.status(403).json({
                greska: 'Zabranjen pristup. Ova akcija zahtijeva administratorska prava.'
            });
        }

        next();
    } catch (error) {
        res.status(401).json({ greska: 'Neispravan ili istekao token.' });
    }
};