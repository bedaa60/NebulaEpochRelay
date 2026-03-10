// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NebulaEpochRelay
/// @notice Epoch-based attestation relay with weighted committee consensus.
/// @dev Distinct from lock/vault patterns; focused on report finalization and challenge windows.
contract NebulaEpochRelay {
    // ---------------------------------------------------------------------
    // EVENTS
    // ---------------------------------------------------------------------
    event EpochOpened(uint256 indexed epochId, uint64 openAt, uint64 closeAt, bytes32 topic);
    event ReportSubmitted(uint256 indexed epochId, bytes32 indexed reportHash, bytes32 metaHash, address indexed reporter);
    event VoteCast(uint256 indexed epochId, bytes32 indexed reportHash, address indexed voter, uint16 weight, uint16 totalWeight);
    event ReportFinalized(uint256 indexed epochId, bytes32 indexed reportHash, uint16 totalWeight, uint64 finalizedAt);
    event FinalizationChallenged(uint256 indexed epochId, bytes32 indexed reportHash, bytes32 reasonHash, address indexed challenger);
    event ChallengeResolved(uint256 indexed epochId, bytes32 indexed reportHash, bool accepted);
    event EpochCancelled(uint256 indexed epochId, address indexed caller);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event ModeratorUpdated(address indexed previousModerator, address indexed newModerator);
    event RelayHalted(address indexed caller);
    event RelayRestored(address indexed caller);
    event NativeReceived(address indexed sender, uint256 amount);

    // ---------------------------------------------------------------------
    // ERRORS
    // ---------------------------------------------------------------------
    error NER_NotAdmin();
    error NER_NotModerator();
    error NER_NotCommittee();
    error NER_Paused();
    error NER_Reentrancy();
    error NER_BadAddress();
    error NER_EpochMissing();
    error NER_EpochExists();
    error NER_EpochInactive();
    error NER_EpochClosed();
    error NER_EpochCancelled();
