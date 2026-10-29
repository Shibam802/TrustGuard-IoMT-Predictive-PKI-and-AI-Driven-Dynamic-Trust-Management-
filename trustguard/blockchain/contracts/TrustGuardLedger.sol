// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title TrustGuardLedger
/// @notice On-chain, tamper-evident audit trail for TrustGuard-IoMT certificate
///         lifecycle events (ISSUE / ROTATE / REVOKE / ESCALATE).
///
/// @dev This replaces the off-chain hash-chained ledger (ledger/ledger.py) with
///      a real blockchain component: every event is a transaction, permanently
///      recorded and independently verifiable by anyone with the contract
///      address -- no need to trust a single off-chain log file. Only the
///      registered CA address (the backend server's wallet) is authorized to
///      write new entries, mirroring the real-world requirement that only the
///      hospital's Certificate Authority may record certificate lifecycle
///      events. Reading entries is public, matching the "auditable" design
///      goal from the Review-1 architecture (papers 3 and 12 in the
///      literature survey use full blockchain consensus for this same
///      purpose; this contract gives the same tamper-evidence with a single
///      authorized writer instead of open consensus, appropriate for a
///      permissioned hospital deployment).
contract TrustGuardLedger is Ownable {
    enum EventType { ISSUE, ROTATE, REVOKE, ESCALATE }

    struct LedgerEntry {
        uint256 index;
        EventType eventType;
        string deviceId;
        string certId;
        string detail;
        uint256 timestamp;
        address recordedBy;
    }

    LedgerEntry[] private entries;

    /// @notice Addresses allowed to write new entries (the CA server's wallet,
    ///         and potentially backup CA nodes in a multi-node deployment).
    mapping(address => bool) public authorizedWriters;

    event EntryRecorded(
        uint256 indexed index,
        EventType indexed eventType,
        string deviceId,
        string certId,
        string detail,
        uint256 timestamp,
        address recordedBy
    );

    event WriterAuthorized(address indexed writer);
    event WriterRevoked(address indexed writer);

    modifier onlyAuthorized() {
        require(
            authorizedWriters[msg.sender] || msg.sender == owner(),
            "TrustGuardLedger: caller is not an authorized CA writer"
        );
        _;
    }

    constructor() Ownable(msg.sender) {
        authorizedWriters[msg.sender] = true;
    }

    /// @notice Grant write access to another address (e.g. a backup CA node).
    function authorizeWriter(address writer) external onlyOwner {
        authorizedWriters[writer] = true;
        emit WriterAuthorized(writer);
    }

    /// @notice Revoke write access from an address.
    function revokeWriter(address writer) external onlyOwner {
        authorizedWriters[writer] = false;
        emit WriterRevoked(writer);
    }

    /// @notice Record a new certificate lifecycle event on-chain.
    /// @dev Called by the Python backend (via web3.py) every time the policy
    ///      controller issues, rotates, or revokes a device certificate.
    function recordEvent(
        EventType eventType,
        string calldata deviceId,
        string calldata certId,
        string calldata detail
    ) external onlyAuthorized returns (uint256) {
        uint256 idx = entries.length;

        entries.push(LedgerEntry({
            index: idx,
            eventType: eventType,
            deviceId: deviceId,
            certId: certId,
            detail: detail,
            timestamp: block.timestamp,
            recordedBy: msg.sender
        }));

        emit EntryRecorded(idx, eventType, deviceId, certId, detail, block.timestamp, msg.sender);
        return idx;
    }

    /// @notice Total number of entries recorded so far.
    function entryCount() external view returns (uint256) {
        return entries.length;
    }

    /// @notice Fetch a single entry by index.
    function getEntry(uint256 index) external view returns (LedgerEntry memory) {
        require(index < entries.length, "TrustGuardLedger: index out of range");
        return entries[index];
    }

    /// @notice Fetch all entries for a given device (linear scan -- fine for
    ///         demo/course-project scale; a production version would index
    ///         this off-chain via events instead).
    function getEntriesForDevice(string calldata deviceId) external view returns (LedgerEntry[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            if (keccak256(bytes(entries[i].deviceId)) == keccak256(bytes(deviceId))) {
                count++;
            }
        }

        LedgerEntry[] memory result = new LedgerEntry[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            if (keccak256(bytes(entries[i].deviceId)) == keccak256(bytes(deviceId))) {
                result[j] = entries[i];
                j++;
            }
        }
        return result;
    }
}
