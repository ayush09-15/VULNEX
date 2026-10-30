/**
 * VULNEX Orchestrator Module
 * Central orchestrator for scan lifecycles, state machine enforcement, and event tracking.
 */

const scanStateMachine = require('./scanStateMachine');
const scanOrchestrator = require('./scanOrchestrator');

module.exports = {
  ...scanStateMachine,
  ...scanOrchestrator
};
