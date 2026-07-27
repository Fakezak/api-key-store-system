const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const ApiKey = require('../models/ApiKey');

class KeyGeneratorService {
    constructor() {
        this.prefix = 'ZAKA';
        this.secretPrefix = 'SEC';
        this.keyLength = 32;
        this.secretLength = 40;
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    }

    /**
     * Generate cryptographically secure random string
     */
    generateSecureString(length = 32) {
        const bytes = crypto.randomBytes(length);
        let result = '';
        for (let i = 0; i < length; i++) {
            result += this.alphabet[bytes[i] % this.alphabet.length];
        }
        return result;
    }

    /**
     * Generate API key with format: PREFIX_RANDOM
     */
    generateApiKey(prefix = this.prefix, length = this.keyLength) {
        const randomPart = this.generateSecureString(length);
        return `${prefix}_${randomPart}`;
    }

    /**
     * Generate secret key with format: PREFIX_RANDOM
     */
    generateSecretKey(prefix = this.secretPrefix, length = this.secretLength) {
        const randomPart = this.generateSecureString(length);
        return `${prefix}_${randomPart}`;
    }

    /**
     * Generate both API key and secret key
     */
    generateKeyPair(options = {}) {
        const {
            prefix = this.prefix,
            secretPrefix = this.secretPrefix,
            keyLength = this.keyLength,
            secretLength = this.secretLength
        } = options;

        const apiKey = this.generateApiKey(prefix, keyLength);
        const secretKey = this.generateSecretKey(secretPrefix, secretLength);
        const keyId = uuidv4();

        return {
            keyId,
            apiKey,
            secretKey,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
        };
    }

    /**
     * Validate API key format
     */
    validateApiKeyFormat(apiKey) {
        const pattern = new RegExp(`^${this.prefix}_[A-Z0-9]{${this.keyLength}}$`);
        return pattern.test(apiKey);
    }

    /**
     * Hash secret key for storage
     */
    hashSecretKey(secretKey) {
        return crypto.createHash('sha256').update(secretKey).digest('hex');
    }

    /**
     * Verify secret key
     */
    verifySecretKey(secretKey, hashedSecret) {
        const hash = this.hashSecretKey(secretKey);
        return crypto.timingSafeEqual(
            Buffer.from(hash),
            Buffer.from(hashedSecret)
        );
    }

    /**
     * Generate store-specific keys
     */
    generateStoreKeys(storeId, storeName) {
        const prefix = `${this.prefix}_${storeName.substring(0, 4).toUpperCase()}`;
        const secretPrefix = `${this.secretPrefix}_${storeName.substring(0, 4).toUpperCase()}`;
        
        return this.generateKeyPair({
            prefix,
            secretPrefix,
            keyLength: this.keyLength,
            secretLength: this.secretLength
        });
    }

    /**
     * Generate custom keys with specific requirements
     */
    generateCustomKeys(customOptions) {
        const {
            storeId,
            storeName,
            keyPrefix = 'ZAKA',
            secretPrefix = 'SEC',
            keyLength = 32,
            secretLength = 40,
            permissions = ['read', 'write'],
            expiresIn = 365 // days
        } = customOptions;

        const keys = this.generateKeyPair({
            prefix: keyPrefix,
            secretPrefix,
            keyLength,
            secretLength
        });

        return {
            ...keys,
            storeId,
            storeName,
            permissions,
            expiresIn,
            expiresAt: new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000),
            status: 'active',
            usageCount: 0,
            lastUsed: null,
            metadata: {
                generatedBy: 'API Key Generator',
                environment: process.env.NODE_ENV || 'development'
            }
        };
    }
}

// Singleton instance
let keyGeneratorInstance = null;

function initializeKeyGenerator() {
    if (!keyGeneratorInstance) {
        keyGeneratorInstance = new KeyGeneratorService();
        console.log('🔑 Key Generator Service initialized');
    }
    return keyGeneratorInstance;
}

function getKeyGenerator() {
    if (!keyGeneratorInstance) {
        throw new Error('Key Generator not initialized. Call initializeKeyGenerator() first.');
    }
    return keyGeneratorInstance;
}

module.exports = {
    KeyGeneratorService,
    initializeKeyGenerator,
    getKeyGenerator
};
