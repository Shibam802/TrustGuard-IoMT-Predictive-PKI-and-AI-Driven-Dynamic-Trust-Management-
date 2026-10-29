// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title TrustGuardLedgerCompact
/// @notice Gas-optimised variant of TrustGuardLedger (DA-9 improvement).
/// @dev Storage keeps only 32-byte hashes of the strings plus one packed slot
///      (timestamp, event type, writer). The full strings are emitted in the
///      event log (cheap: ~8 gas per byte) and can be re-hashed by an
///      auditor and compared against the stored hashes.
contract TrustGuardLedgerCompact is Ownable {
    enum EventType { ISSUE, ROTATE, REVOKE, ESCALATE }

    struct Entry {
        uint64 timestamp;     // \
        EventType eventType;  //  } packed into one 32-byte slot
        address recordedBy;   // /
        bytes32 deviceHash;
        bytes32 certHash;
        bytes32 detailHash;
    }

    Entry[] private entries;
    mapping(address => bool) public authorizedWriters;

    event EntryRecorded(uint256 indexed index, EventType indexed eventType,
        string deviceId, string certId, string detail);

    modifier onlyAuthorized() {
        require(authorizedWriters[msg.sender] || msg.sender == owner(),
            "TrustGuardLedger: caller is not an authorized CA writer");
        _;
    }

    constructor() Ownable(msg.sender) { authorizedWriters[msg.sender] = true; }

    function authorizeWriter(address w) external onlyOwner { authorizedWriters[w] = true; }
    function revokeWriter(address w) external onlyOwner { authorizedWriters[w] = false; }

    function recordEvent(EventType t, string calldata deviceId,
        string calldata certId, string calldata detail)
        external onlyAuthorized returns (uint256 idx)
    {
        idx = entries.length;
        entries.push(Entry({
            timestamp: uint64(block.timestamp), eventType: t, recordedBy: msg.sender,
            deviceHash: keccak256(bytes(deviceId)),
            certHash: keccak256(bytes(certId)),
            detailHash: keccak256(bytes(detail))
        }));
        emit EntryRecorded(idx, t, deviceId, certId, detail);
    }

    function entryCount() external view returns (uint256) { return entries.length; }

    function getEntry(uint256 i) external view returns (Entry memory) {
        require(i < entries.length, "TrustGuardLedger: index out of range");
        return entries[i];
    }

    /// @notice True if the supplied strings hash to what was stored at index i.
    function verifyEntry(uint256 i, string calldata deviceId,
        string calldata certId, string calldata detail) external view returns (bool) {
        require(i < entries.length, "TrustGuardLedger: index out of range");
        Entry storage e = entries[i];
        return e.deviceHash == keccak256(bytes(deviceId))
            && e.certHash == keccak256(bytes(certId))
            && e.detailHash == keccak256(bytes(detail));
    }
}
