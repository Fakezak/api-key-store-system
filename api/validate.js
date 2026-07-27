const { KeyGeneratorService } = require('../utils/keyGenerator');

const generator = new KeyGeneratorService();

module.exports = async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    try {
        if (req.method !== 'POST') {
            return res.status(405).json({
                success: false,
                message: 'Method not allowed'
            });
        }

        const { apiKey } = req.body;

        if (!apiKey) {
            return res.status(400).json({
                success: false,
                message: 'API key is required'
            });
        }

        const isValid = generator.validateApiKeyFormat(apiKey);

        res.status(200).json({
            success: true,
            data: {
                isValid,
                format: 'ZAKA_XXXXXXXX... (32 chars)'
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Validation failed',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};
