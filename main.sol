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
    error NER_ReportMissing();
    error NER_AlreadyVoted();
    error NER_AlreadyFinalized();
    error NER_WeightTooLow();
    error NER_ThresholdNotReached();
    error NER_ChallengeWindowGone();
    error NER_NotFinalized();
    error NER_CallFailed();
    error NER_BadTiming();
    error NER_EmptyBytes();

    // ---------------------------------------------------------------------
    // CONSTANTS
    // ---------------------------------------------------------------------
    uint8 public constant MAJOR = 1;
    uint16 public constant FINALIZE_THRESHOLD = 650;
    uint16 public constant TOTAL_COMMITTEE_WEIGHT = 1000;
    uint64 public constant MIN_EPOCH_DURATION = 15 minutes;
    uint64 public constant MAX_EPOCH_DURATION = 21 days;
    uint64 public constant CHALLENGE_WINDOW = 18 hours;
    bytes32 public constant RELAY_NAMESPACE = keccak256("NebulaEpochRelay.Core");
    bytes32 public constant RELAY_SEED_A = 0x6cf0a2da7d6cb0d7f23562efce9b86f2ed79384c144897f0661183f6de4cdf77;
    bytes32 public constant RELAY_SEED_B = 0x9de4cb612f6b149e4f32c3704ab4f5f3f50378c019498d88db5fd4f56a4def3a;

    // ---------------------------------------------------------------------
    // IMMUTABLE COMMITTEE
    // ---------------------------------------------------------------------
    address public immutable nodeA;
    address public immutable nodeB;
    address public immutable nodeC;
    address public immutable nodeD;

    // ---------------------------------------------------------------------
    // STORAGE
    // ---------------------------------------------------------------------
    struct Epoch {
        bytes32 topic;
        uint64 openAt;
        uint64 closeAt;
        bool cancelled;
        bool exists;
    }

    struct ReportState {
        bytes32 metaHash;
        address reporter;
        uint16 aggregateWeight;
        uint64 finalizedAt;
        bool finalized;
        bool challenged;
        bool challengeAccepted;
    }

    address public admin;
    address public moderator;
    bool private _paused;
    uint256 private _guard;

    mapping(uint256 => Epoch) private _epochs;
    mapping(uint256 => mapping(bytes32 => ReportState)) private _reports;
    mapping(uint256 => mapping(bytes32 => uint16)) private _voteWeightByReport;
    mapping(uint256 => mapping(bytes32 => mapping(address => bool))) private _didVote;

    // ---------------------------------------------------------------------
    // CONSTRUCTOR
    // ---------------------------------------------------------------------
    constructor() {
        admin = 0x9191919191919191919191919191919191919191;
        moderator = 0x2828282828282828282828282828282828282828;
        nodeA = 0x7000700070007000700070007000700070007000;
        nodeB = 0x1337133713371337133713371337133713371337;
        nodeC = 0x4242424242424242424242424242424242424242;
        nodeD = 0x5656565656565656565656565656565656565656;
    }
