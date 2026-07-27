const mongoose = require('mongoose');

const apiKeySchema = new mongoose.Schema({
    keyId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    apiKey: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    secretKeyHash: {
        type: String,
        required: true,
        select: false
    },
    // For store/merchant identification
    storeId: {
        type: String,
        required: true,
        index: true
    },
    storeName: {
        type: String,
        required: true
    },
    // Permissions and access control
    permissions: [{
        type: String,
        enum: ['read', 'write', 'delete', 'admin', 'manage_users', 'view_reports'],
        default: ['read', 'write']
    }],
    // Key metadata
    name: {
        type: String,
        trim: true
    },
    description: {
        type: String,
        trim: true
    },
    environment: {
        type: String,
        enum: ['development', 'staging', 'production'],
        default: 'production'
    },
    // Status and lifecycle
    status: {
        type: String,
        enum: ['active', 'inactive', 'expired', 'revoked', 'pending'],
        default: 'active'
    },
    // Usage tracking
    usageCount: {
        type: Number,
        default: 0
    },
    lastUsed: {
        type: Date,
        default: null
    },
    // Rate limiting
    rateLimit: {
        requestsPerMinute: {
            type: Number,
            default: 60
        },
        requestsPerDay: {
            type: Number,
            default: 10000
        }
    },
    // IP whitelist
    allowedIps: [{
        type: String
    }],
    // Expiration
    expiresAt: {
        type: Date,
        required: true
    },
    // Audit trail
    createdBy: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    revokedAt: {
        type: Date,
        default: null
    },
    revokedReason: {
        type: String,
        default: null
    },
    // Metadata
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    }
}, {
    timestamps: true,
    toJSON: {
        transform: function(doc, ret) {
            delete ret.__v;
            delete ret.secretKeyHash;
            return ret;
        }
    }
});

// Indexes for performance
apiKeySchema.index({ apiKey: 1 }, { unique: true });
apiKeySchema.index({ storeId: 1, status: 1 });
apiKeySchema.index({ expiresAt: 1 });
apiKeySchema.index({ createdAt: -1 });

// Methods
apiKeySchema.methods.incrementUsage = async function() {
    this.usageCount += 1;
    this.lastUsed = new Date();
    return this.save();
};

apiKeySchema.methods.revoke = async function(reason = 'Revoked by admin') {
    this.status = 'revoked';
    this.revokedAt = new Date();
    this.revokedReason = reason;
    return this.save();
};

apiKeySchema.methods.isExpired = function() {
    return this.expiresAt && new Date() > this.expiresAt;
};

apiKeySchema.methods.isActive = function() {
    return this.status === 'active' && !this.isExpired();
};

// Static methods
apiKeySchema.statics.findByApiKey = function(apiKey) {
    return this.findOne({ apiKey });
};

apiKeySchema.statics.findActiveByStore = function(storeId) {
    return this.find({
        storeId,
        status: 'active',
        expiresAt: { $gt: new Date() }
    });
};

apiKeySchema.statics.cleanupExpired = async function() {
    const result = await this.updateMany(
        { 
            expiresAt: { $lt: new Date() },
            status: 'active'
        },
        { 
            $set: { 
                status: 'expired',
                updatedAt: new Date()
            }
        }
    );
    console.log(`Cleaned up ${result.nModified} expired keys`);
    return result;
};

module.exports = mongoose.model('ApiKey', apiKeySchema);
