const express = require('express');
const authController = require('../controllers/auth');
const router = express.Router();

router.post("/register",authController.register);
router.post("/login",authController.login);
router.post("/dashboard",authController.dashboard);
router.post("/data",authController.data);

module.exports = router;