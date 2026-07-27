const { KeyGeneratorService } = require('../utils/keyGenerator');

// Initialize generator
const generator = new KeyGeneratorService();

module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    // Handle preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    try {
        // Only allow POST requests
        if (req.method !== 'POST') {
            return res.status(405).json({
                success: false,
                message: 'Method not allowed. Use POST.'
            });
        }

        const {
            storeId = `STORE_${Date.now()}`,
            storeName = 'My Store',
            permissions = ['read', 'write'],
            environment = 'production',
            expiresIn = 365,
            keyLength = 32,
            secretLength = 40
        } = req.body || {};

        // Generate keys
        const keyData = generator.generateCustomKeys({
            storeId,
            storeName,
            permissions,
            environment,
            expiresIn,
            keyLength,
            secretLength,
            prefix: 'ZAKA',
            secretPrefix: 'SEC'
        });

        // For Vercel, we'll store in memory (or you can use Vercel KV)
        // For production, use a database like MongoDB Atlas or Vercel KV
        const response = {
            success: true,
            data: {
                keyId: keyData.keyId,
                apiKey: keyData.apiKey,
                secretKey: keyData.secretKey,
                storeId: keyData.storeId,
                storeName: keyData.storeName,
                permissions: keyData.permissions,
                environment: keyData.environment,
                expiresAt: keyData.expiresAt,
                createdAt: keyData.createdAt,
                // Security: Don't send this in production
                // secretKeyHash: keyData.secretKeyHash
            },
            message: 'API key generated successfully! Store your secret key securely.'
        };

        // Log for debugging
        console.log(`✅ API Key generated for ${storeName} (${storeId})`);

        return res.status(201).json(response);

    } catch (error) {
        console.error('❌ Error generating API key:', error);
        
        return res.status(500).json({
            success: false,
            message: 'Failed to generate API key',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};
