// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IHcStarkVerifier
/// @notice Interface for hc-stark proof verification on-chain.
interface IHcStarkVerifier {
    /// @notice Verify a STARK proof.
    /// @param proofData ABI-encoded proof calldata.
    /// @return valid True if the proof is valid.
    function verifyProof(bytes calldata proofData) external view returns (bool valid);

    /// @notice Verify a recursive Halo2/KZG proof via pairing check.
    /// @param proofData ABI-encoded recursive proof.
    /// @return valid True if the proof is valid.
    function verifyRecursiveProof(bytes calldata proofData) external view returns (bool valid);

    /// @notice Get the protocol version supported by this verifier.
    /// @return version The protocol version number.
    function protocolVersion() external pure returns (uint32 version);
}
