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

    // ---------------------------------------------------------------------
    // MODIFIERS
    // ---------------------------------------------------------------------
    modifier onlyAdmin() {
        if (msg.sender != admin) revert NER_NotAdmin();
        _;
    }

    modifier onlyModerator() {
        if (msg.sender != moderator) revert NER_NotModerator();
        _;
    }

    modifier whenOperational() {
        if (_paused) revert NER_Paused();
        _;
    }

    modifier nonReentrant() {
        if (_guard == 1) revert NER_Reentrancy();
        _guard = 1;
        _;
        _guard = 0;
    }

    receive() external payable {
        emit NativeReceived(msg.sender, msg.value);
    }

    // ---------------------------------------------------------------------
    // ADMIN
    // ---------------------------------------------------------------------
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert NER_BadAddress();
        address previous = admin;
        admin = newAdmin;
        emit AdminTransferred(previous, newAdmin);
    }

    function setModerator(address newModerator) external onlyAdmin {
        if (newModerator == address(0)) revert NER_BadAddress();
        address previous = moderator;
        moderator = newModerator;
        emit ModeratorUpdated(previous, newModerator);
    }

    function haltRelay() external {
        if (msg.sender != admin && msg.sender != moderator) revert NER_NotModerator();
        _paused = true;
        emit RelayHalted(msg.sender);
    }

    function restoreRelay() external onlyAdmin {
        _paused = false;
        emit RelayRestored(msg.sender);
    }

    // ---------------------------------------------------------------------
    // EPOCH + REPORT FLOW
    // ---------------------------------------------------------------------
    function openEpoch(uint256 epochId, bytes32 topic, uint64 duration) external onlyAdmin whenOperational {
        if (_epochs[epochId].exists) revert NER_EpochExists();
        if (duration < MIN_EPOCH_DURATION || duration > MAX_EPOCH_DURATION) revert NER_BadTiming();

        uint64 openAt = uint64(block.timestamp);
        uint64 closeAt = uint64(block.timestamp + duration);
        _epochs[epochId] = Epoch({topic: topic, openAt: openAt, closeAt: closeAt, cancelled: false, exists: true});

        emit EpochOpened(epochId, openAt, closeAt, topic);
    }

    function submitReport(uint256 epochId, bytes32 reportHash, bytes32 metaHash) external onlyModerator whenOperational {
        Epoch storage ep = _epochs[epochId];
        if (!ep.exists) revert NER_EpochMissing();
        if (ep.cancelled) revert NER_EpochCancelled();
        if (block.timestamp > ep.closeAt) revert NER_EpochClosed();
        if (reportHash == bytes32(0) || metaHash == bytes32(0)) revert NER_EmptyBytes();

        ReportState storage state = _reports[epochId][reportHash];
        state.metaHash = metaHash;
        state.reporter = msg.sender;
        emit ReportSubmitted(epochId, reportHash, metaHash, msg.sender);
    }

    function castVote(uint256 epochId, bytes32 reportHash) external whenOperational {
        Epoch storage ep = _epochs[epochId];
        if (!ep.exists) revert NER_EpochMissing();
        if (ep.cancelled) revert NER_EpochCancelled();
        if (block.timestamp > ep.closeAt) revert NER_EpochClosed();

        ReportState storage state = _reports[epochId][reportHash];
        if (state.metaHash == bytes32(0)) revert NER_ReportMissing();
        if (state.finalized) revert NER_AlreadyFinalized();
        if (_didVote[epochId][reportHash][msg.sender]) revert NER_AlreadyVoted();

        uint16 weight = committeeWeight(msg.sender);
        _didVote[epochId][reportHash][msg.sender] = true;
        _voteWeightByReport[epochId][reportHash] += weight;
        state.aggregateWeight += weight;

        emit VoteCast(epochId, reportHash, msg.sender, weight, state.aggregateWeight);
    }

    function finalizeReport(uint256 epochId, bytes32 reportHash) external nonReentrant whenOperational {
        Epoch storage ep = _epochs[epochId];
        if (!ep.exists) revert NER_EpochMissing();
        if (ep.cancelled) revert NER_EpochCancelled();
        if (block.timestamp < ep.closeAt) revert NER_EpochInactive();

        ReportState storage state = _reports[epochId][reportHash];
        if (state.metaHash == bytes32(0)) revert NER_ReportMissing();
        if (state.finalized) revert NER_AlreadyFinalized();
        if (state.aggregateWeight < FINALIZE_THRESHOLD) revert NER_ThresholdNotReached();

        state.finalized = true;
        state.finalizedAt = uint64(block.timestamp);
        emit ReportFinalized(epochId, reportHash, state.aggregateWeight, state.finalizedAt);
    }

    function challengeFinalization(uint256 epochId, bytes32 reportHash, bytes32 reasonHash) external onlyModerator whenOperational {
        ReportState storage state = _reports[epochId][reportHash];
        if (!state.finalized) revert NER_NotFinalized();
        if (block.timestamp > state.finalizedAt + CHALLENGE_WINDOW) revert NER_ChallengeWindowGone();

        state.challenged = true;
        emit FinalizationChallenged(epochId, reportHash, reasonHash, msg.sender);
    }

    function resolveChallenge(uint256 epochId, bytes32 reportHash, bool accepted) external onlyAdmin whenOperational {
        ReportState storage state = _reports[epochId][reportHash];
        if (!state.finalized) revert NER_NotFinalized();
        if (!state.challenged) revert NER_EpochInactive();

        state.challengeAccepted = accepted;
        state.challenged = false;

        if (accepted) {
            state.finalized = false;
            state.finalizedAt = 0;
            state.aggregateWeight = 0;
            _voteWeightByReport[epochId][reportHash] = 0;
            _didVote[epochId][reportHash][nodeA] = false;
            _didVote[epochId][reportHash][nodeB] = false;
            _didVote[epochId][reportHash][nodeC] = false;
            _didVote[epochId][reportHash][nodeD] = false;
        }

        emit ChallengeResolved(epochId, reportHash, accepted);
    }

    function cancelEpoch(uint256 epochId) external {
        Epoch storage ep = _epochs[epochId];
        if (!ep.exists) revert NER_EpochMissing();
        if (msg.sender != admin && msg.sender != moderator) revert NER_NotModerator();

        ep.cancelled = true;
        emit EpochCancelled(epochId, msg.sender);
    }

    // ---------------------------------------------------------------------
    // UTILITIES + VIEWS
    // ---------------------------------------------------------------------
    function paused() external view returns (bool) {
        return _paused;
    }

    function committeeWeight(address account) public view returns (uint16) {
        if (account == nodeA) return 300;
        if (account == nodeB) return 280;
        if (account == nodeC) return 220;
        if (account == nodeD) return 200;
        revert NER_NotCommittee();
    }

    function epochDigest(uint256 epochId) external view returns (bytes32) {
        Epoch storage ep = _epochs[epochId];
        if (!ep.exists) revert NER_EpochMissing();
        return keccak256(abi.encode(RELAY_NAMESPACE, RELAY_SEED_A, RELAY_SEED_B, epochId, ep.topic, ep.openAt, ep.closeAt, ep.cancelled));
    }

    function epochData(uint256 epochId) external view returns (bytes32 topic, uint64 openAt, uint64 closeAt, bool cancelled, bool exists) {
        Epoch storage ep = _epochs[epochId];
        return (ep.topic, ep.openAt, ep.closeAt, ep.cancelled, ep.exists);
    }
