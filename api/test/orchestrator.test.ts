import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { fastify, verifyAdminAuth, checkRateLimit, pool } from '../src/server.js';

describe('Fastify Orchestration Layer Suite', () => {
    after(async () => {
        await fastify.close();
        await pool.end().catch(() => {});
    });

    test('GET / returns 200 with service information and endpoints', async () => {
        const response = await fastify.inject({
            method: 'GET',
            url: '/',
        });

        assert.equal(response.statusCode, 200);
        const data = response.json();
        assert.equal(data.status, 'online');
        assert.equal(data.service, 'Compliance-Aware Block Builder API & WebSocket Gateway');
        assert.ok(data.endpoints.health);
        assert.ok(data.endpoints.decisions);
        assert.ok(data.endpoints.bids);
    });

    describe('Admin Authentication & Security Headers', () => {
        test('verifyAdminAuth accepts matching x-admin-key', () => {
            const req = {
                headers: { 'x-admin-key': 'dev-admin-secret-2026' },
            };
            assert.equal(verifyAdminAuth(req), true);
        });

        test('verifyAdminAuth accepts matching Bearer authorization token', () => {
            const req = {
                headers: { authorization: 'Bearer dev-admin-secret-2026' },
            };
            assert.equal(verifyAdminAuth(req), true);
        });

        test('verifyAdminAuth rejects invalid or missing credentials', () => {
            assert.equal(verifyAdminAuth({ headers: {} }), false);
            assert.equal(verifyAdminAuth({ headers: { 'x-admin-key': 'wrong-password' } }), false);
            assert.equal(verifyAdminAuth({ headers: { authorization: 'Bearer wrong-token' } }), false);
        });
    });

    describe('Sliding Window Rate Limiter', () => {
        test('checkRateLimit enforces maximum request threshold per window', () => {
            const testKey = `test_limit_${Date.now()}`;
            const max = 3;
            const windowMs = 5000;

            // 3 requests allowed
            assert.equal(checkRateLimit(testKey, max, windowMs), true);
            assert.equal(checkRateLimit(testKey, max, windowMs), true);
            assert.equal(checkRateLimit(testKey, max, windowMs), true);

            // 4th request within window must be rate limited
            assert.equal(checkRateLimit(testKey, max, windowMs), false);
        });
    });

    describe('Endpoint Validation & Authorization Guards', () => {
        test('POST /api/policy/activate rejects unauthenticated calls with 401', async () => {
            const response = await fastify.inject({
                method: 'POST',
                url: '/api/policy/activate',
                payload: { policy_id: 'institution-standard-v1' },
            });

            assert.equal(response.statusCode, 401);
            const data = response.json();
            assert.match(data.error, /Unauthorized/i);
        });

        test('POST /api/policy/activate requires policy_id in request body', async () => {
            const response = await fastify.inject({
                method: 'POST',
                url: '/api/policy/activate',
                headers: { 'x-admin-key': 'dev-admin-secret-2026' },
                payload: {},
            });

            assert.equal(response.statusCode, 400);
            const data = response.json();
            assert.match(data.error, /policy_id is required/i);
        });

        test('POST /api/admin/refresh rejects missing or invalid Bearer token with 401', async () => {
            const noAuthResp = await fastify.inject({
                method: 'POST',
                url: '/api/admin/refresh',
            });
            assert.equal(noAuthResp.statusCode, 401);

            const badTokenResp = await fastify.inject({
                method: 'POST',
                url: '/api/admin/refresh',
                headers: { authorization: 'Bearer invalid-token' },
            });
            assert.equal(badTokenResp.statusCode, 401);
        });

        test('POST /api/compliance/identity/revoke requires valid Ethereum address', async () => {
            // Missing admin auth -> 401
            const unauthResp = await fastify.inject({
                method: 'POST',
                url: '/api/compliance/identity/revoke',
                payload: { applicant: '0x1111111111111111111111111111111111111111' },
            });
            assert.equal(unauthResp.statusCode, 401);

            // Valid auth, but invalid address format -> 400
            const badAddrResp = await fastify.inject({
                method: 'POST',
                url: '/api/compliance/identity/revoke',
                headers: { 'x-admin-key': 'dev-admin-secret-2026' },
                payload: { applicant: 'not-an-eth-address' },
            });
            assert.equal(badAddrResp.statusCode, 400);
            assert.match(badAddrResp.json().error, /Valid applicant Ethereum address/i);
        });
    });
});
