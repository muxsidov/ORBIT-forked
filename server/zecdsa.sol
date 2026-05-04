// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureVerifier {
    // Funds
    receive() external payable {}
    function deposit() external payable {}

    mapping(bytes32 => bool) public usedSignatureHashes;

    function getMessageHash(address _to, uint256 _amount, string memory _message) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount, _message));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function verify(
        address _signer,
        address payable _to,
        uint256 _amount,
        string memory _message,
        bytes memory signature
    ) public payable returns (bool){
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        // Ensure signature is not redeemed before and if it is not, store it and continue.
        bytes32 signatureHash = keccak256(abi.encodePacked(r, s, v, _message));
        require(!usedSignatureHashes[signatureHash], "Signature already used");
        usedSignatureHashes[signatureHash] = true;

        bytes32 messageHash = getMessageHash(_to, _amount, _message);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        // Here we can send the coin if signature verify
        if (recoverSigner(ethSignedMessageHash, signature) == _signer){
            uint256 amountInWei = 0.00001 ether;
            require(address(this).balance >= amountInWei, "Insufficient contract balance");

            (bool success, ) = _to.call{value: amountInWei}("");
            require(success, "Transfer failed");
            return true;
        }
        else{
            return false;
        }
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return (r, s, v);
    }


    function nothing()
        public
        pure
    {
        
    }
}
