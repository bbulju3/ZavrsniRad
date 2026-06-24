const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    // Dohvaćamo token iz Authorization zaglavlja (Header)
    const authHeader = req.headers['authorization'];

    // Token dolazi u formatu: "Bearer KOD_TOKENA", pa ga splitamo po razmaku
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ greska: 'Pristup odbijen. Token nije proslijeđen.' });
    }

    try {
        const dekodiraniKorisnik = jwt.verify(token, process.env.JWT_SECRET);

        req.user = dekodiraniKorisnik;

        next();
    } catch (error) {
        return res.status(403).json({ greska: 'JWT token je istekao ili je neispravan.' });
    }
};