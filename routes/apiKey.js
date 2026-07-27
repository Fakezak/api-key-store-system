const express = require('express');
const router = express.Router();
const { body, validationResult, param } = require('express-validator');
const ApiKey = require('../models/ApiKey');
const { getKeyGenerator } = require('../services/keyGenerator');
const { authenticate, authorize } = require('../middleware/auth');
const { validateApiKey } = require('../middleware/validator');

// Generate new API key for a store
router.post('/generate',
    authenticate,
    [
        body('storeId').isString().notEmpty().withMessage('Store ID is required'),
        body('storeName').isString().notEmpty().withMessage('Store name is required'),
        body('permissions').optional().isArray().withMessage('Permissions must be an array'),
        body('environment').optional().isIn(['development', 'staging', 'production']),
        body('expiresIn').optional().isInt({ min: 1, max: 3650 }).withMessage('Expiry must be between 1 and 3650 days'),
        body('rateLimit').optional().isObject()
    ],
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const generator = getKeyGenerator();
            const {
                storeId,
                storeName,
                permissions = ['read', 'write'],
                environment = 'production',
                expiresIn = 365,
                rateLimit = { requestsPerMinute: 60, requestsPerDay: 10000 }
            } = req.body;

            // Generate keys
            const keyData = generator.generateCustomKeys({
                storeId,
                storeName,
                permissions,
                expiresIn
            });

            // Hash secret key for storage
            const secretKeyHash = generator.hashSecretKey(keyData.secretKey);

            // Create API key record
            const apiKey = new ApiKey({
                keyId: keyData.keyId,
                apiKey: keyData.apiKey,
                secretKeyHash,
                storeId,
                storeName,
                permissions,
                environment,
                name: `${storeName} - ${environment}`,
                expiresAt: keyData.expiresAt,
                createdBy: req.user?.id || 'system',
                rateLimit,
                metadata: keyData.metadata
            });

            await apiKey.save();

            // Log activity
            console.log(`🔑 New API key generated for store: ${storeName} (${storeId})`);

            res.status(201).json({
                success: true,
                data: {
                    keyId: keyData.keyId,
                    apiKey: keyData.apiKey,
                    secretKey: keyData.secretKey,
                    expiresAt: keyData.expiresAt,
                    permissions,
                    storeId,
                    storeName,
                    environment,
                    rateLimit
                },
                message: 'API key generated successfully. Store secret key securely!'
            });
        } catch (error) {
            next(error);
        }
    }
);

// Get all API keys for a store
router.get('/store/:storeId',
    authenticate,
    authorize(['admin', 'manage_users']),
    async (req, res, next) => {
        try {
            const { storeId } = req.params;
            const { status, environment } = req.query;

            const query = { storeId };
            if (status) query.status = status;
            if (environment) query.environment = environment;

            const keys = await ApiKey.find(query)
                .sort({ createdAt: -1 })
                .limit(100);

            const total = await ApiKey.countDocuments(query);

            res.json({
                success: true,
                data: {
                    keys,
                    total,
                    limit: 100
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// Get single API key
router.get('/:keyId',
    authenticate,
    authorize(['admin', 'manage_users']),
    async (req, res, next) => {
        try {
            const { keyId } = req.params;
            const apiKey = await ApiKey.findOne({ keyId });

            if (!apiKey) {
                return res.status(404).json({
                    success: false,
                    message: 'API key not found'
                });
            }

            res.json({
                success: true,
                data: apiKey
            });
        } catch (error) {
            next(error);
        }
    }
);

// Revoke API key
router.patch('/:keyId/revoke',
    authenticate,
    authorize(['admin']),
    [
        body('reason').optional().isString().withMessage('Reason must be a string')
    ],
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { keyId } = req.params;
            const { reason = 'Revoked by admin' } = req.body;

            const apiKey = await ApiKey.findOne({ keyId });
            if (!apiKey) {
                return res.status(404).json({
                    success: false,
                    message: 'API key not found'
                });
            }

            await apiKey.revoke(reason);

            res.json({
                success: true,
                message: 'API key revoked successfully',
                data: {
                    keyId: apiKey.keyId,
                    status: apiKey.status,
                    revokedAt: apiKey.revokedAt
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// Validate API key (for middleware usage)
router.post('/validate',
    [
        body('apiKey').isString().notEmpty().withMessage('API key is required')
    ],
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { apiKey } = req.body;
            const keyRecord = await ApiKey.findOne({ 
                apiKey,
                status: 'active',
                expiresAt: { $gt: new Date() }
            });

            if (!keyRecord) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid or expired API key'
                });
            }

            // Increment usage count
            await keyRecord.incrementUsage();

            res.json({
                success: true,
                data: {
                    storeId: keyRecord.storeId,
                    storeName: keyRecord.storeName,
                    permissions: keyRecord.permissions,
                    rateLimit: keyRecord.rateLimit
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// Update API key settings
router.patch('/:keyId',
    authenticate,
    authorize(['admin', 'manage_users']),
    [
        body('name').optional().isString(),
        body('description').optional().isString(),
        body('permissions').optional().isArray(),
        body('rateLimit').optional().isObject(),
        body('status').optional().isIn(['active', 'inactive'])
    ],
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { keyId } = req.params;
            const updateData = req.body;
            updateData.updatedAt = new Date();

            const apiKey = await ApiKey.findOneAndUpdate(
                { keyId },
                { $set: updateData },
                { new: true, runValidators: true }
            );

            if (!apiKey) {
                return res.status(404).json({
                    success: false,
                    message: 'API key not found'
                });
            }

            res.json({
                success: true,
                data: apiKey,
                message: 'API key updated successfully'
            });
        } catch (error) {
            next(error);
        }
    }
);

// Delete API key
router.delete('/:keyId',
    authenticate,
    authorize(['admin']),
    async (req, res, next) => {
        try {
            const { keyId } = req.params;
            const apiKey = await ApiKey.findOneAndDelete({ keyId });

            if (!apiKey) {
                return res.status(404).json({
                    success: false,
                    message: 'API key not found'
                });
            }

            res.json({
                success: true,
                message: 'API key deleted successfully'
            });
        } catch (error) {
            next(error);
        }
    }
);

// Bulk generate keys (admin only)
router.post('/generate/bulk',
    authenticate,
    authorize(['admin']),
    [
        body('stores').isArray().withMessage('Stores must be an array'),
        body('stores.*.storeId').isString().notEmpty(),
        body('stores.*.storeName').isString().notEmpty()
    ],
    async (req, res, next) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { stores } = req.body;
            const generator = getKeyGenerator();
            const results = [];

            for (const store of stores) {
                const keyData = generator.generateStoreKeys(store.storeId, store.storeName);
                const secretKeyHash = generator.hashSecretKey(keyData.secretKey);

                const apiKey = new ApiKey({
                    keyId: keyData.keyId,
                    apiKey: keyData.apiKey,
                    secretKeyHash,
                    storeId: store.storeId,
                    storeName: store.storeName,
                    permissions: ['read', 'write'],
                    environment: 'production',
                    expiresAt: keyData.expiresAt,
                    createdBy: req.user.id,
                    name: `${store.storeName} - Production`
                });

                await apiKey.save();

                results.push({
                    storeId: store.storeId,
                    storeName: store.storeName,
                    apiKey: keyData.apiKey,
                    secretKey: keyData.secretKey,
                    expiresAt: keyData.expiresAt
                });
            }

            res.status(201).json({
                success: true,
                data: results,
                message: `${results.length} API keys generated successfully`
            });
        } catch (error) {
            next(error);
        }
    }
);

module.exports = router;
