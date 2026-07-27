const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class KeyGeneratorService {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    }

    /**
     * Generate cryptographically secure random string
     */
    generateSecureString(length = 32) {
        try {
            const bytes = crypto.randomBytes(length);
            let result = '';
            for (let i = 0; i < length; i++) {
                result += this.alphabet[bytes[i] % this.alphabet.length];
            }
            return result;
        } catch (error) {
            // Fallback for older Node versions
            let result = '';
            for (let i = 0; i < length; i++) {
                result += this.alphabet[Math.floor(Math.random() * this.alphabet.length)];
            }
            return result;
        }
    }

    /**
     * Generate API key with format: PREFIX_RANDOM
     */
    generateApiKey(prefix = 'ZAKA', length = 32) {
        const randomPart = this.generateSecureString(length);
        return `${prefix}_${randomPart}`;
    }

    /**
     * Generate secret key
     */
    generateSecretKey(prefix = 'SEC', length = 40) {
        const randomPart = this.generateSecureString(length);
        return `${prefix}_${randomPart}`;
    }

    /**
     * Generate complete key pair
     */
    generateKeyPair(options = {}) {
        const {
            prefix = 'ZAKA',
            secretPrefix = 'SEC',
            keyLength = 32,
            secretLength = 40
        } = options;

        const apiKey = this.generateApiKey(prefix, keyLength);
        const secretKey = this.generateSecretKey(secretPrefix, secretLength);
        const keyId = uuidv4();

        return {
            keyId,
            apiKey,
            secretKey,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        };
    }

    /**
     * Generate store-specific custom keys
     */
    generateCustomKeys(customOptions) {
        const {
            storeId = `STORE_${Date.now()}`,
            storeName = 'My Store',
            prefix = 'ZAKA',
            secretPrefix = 'SEC',
            keyLength = 32,
            secretLength = 40,
            permissions = ['read', 'write'],
            environment = 'production',
            expiresIn = 365
        } = customOptions;

        const keys = this.generateKeyPair({
            prefix,
            secretPrefix,
            keyLength,
            secretLength
        });

        return {
            ...keys,
            storeId,
            storeName,
            permissions,
            environment,
            expiresIn,
            expiresAt: new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000).toISOString(),
            status: 'active',
            metadata: {
                generatedBy: 'API Key Generator',
                environment: process.env.NODE_ENV || 'development',
                timestamp: new Date().toISOString()
            }
        };
    }

    /**
     * Validate API key format
     */
    validateApiKeyFormat(apiKey, prefix = 'ZAKA') {
        const pattern = new RegExp(`^${prefix}_[A-Z0-9]{32}$`);
        return pattern.test(apiKey);
    }

    /**
     * Hash secret key
     */
    hashSecretKey(secretKey) {
        return crypto.createHash('sha256').update(secretKey).digest('hex');
    }
}

module.exports = {
    KeyGeneratorService
};
