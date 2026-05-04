// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Modified from : https://github.com/kaleido-io/token-sample-htlc/blob/master/contracts/HashedTimelockERC20.sol



/**
 * @dev Hashed Timelock Contracts (HTLCs) for native ETH.
 *
 * Protocol:
 *
 *  1) newContract(receiver, hashlock, timelock) - sender calls this payable
 *     to create a new HTLC with ETH. A 32-byte contractId is returned.
 *  2) withdraw(contractId, preimage) - once the receiver knows the preimage
 *     for the hashlock, they can claim the ETH.
 *  3) refund(contractId) - after timelock has expired and if the receiver
 *     has not withdrawn, the sender can get their ETH back.
 */
contract HashedTimelockETH {
    struct G1Point { uint256 x; uint256 y; }
    struct G2Point { uint256[2] x; uint256[2] y; }

    bool is_set = false;
    struct Param{
        G1Point g;
        G2Point g2;
        G1Point g1a;
        G2Point g2b;
        G1Point u0;
        G1Point[40] u_vec;
    }
    struct Preimage{
        G1Point sk1;
        G1Point sk2;
        G2Point sk3;
    }
    Param public param;

    // Set public parameter 
    function setup(Param memory _param) public returns (bool){
        if (!is_set){
            for (uint256 i = 0; i < 40; i++) {
                param.u_vec[i] = _param.u_vec[i];
            }
            param.g = _param.g;
            param.g2 = _param.g2;
            param.g1a = _param.g1a;
            param.g2b = _param.g2b;
            param.u0 = _param.u0;

            is_set = true;
        }

        return true;
    }   

    function G1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    function G2() internal pure returns (G2Point memory p) {
        p.x = [
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634)
        ];
        p.y = [
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531)
        ];
    }
    function add(G1Point memory p1, G1Point memory p2)
        public view returns (G1Point memory r)
    {
        uint256[4] memory input = [p1.x, p1.y, p2.x, p2.y];
        bool success;
        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }
        require(success, "G1 add failed");
    }
    function mul(G1Point memory p, uint256 s)
        internal view returns (G1Point memory r)
    {
        uint256[3] memory input = [p.x, p.y, s];
        bool success;
        assembly {
            success := staticcall(gas(), 0x07, input, 0x60, r, 0x40)
        }
        require(success, "G1 mul failed");
    }


    uint256 internal constant FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// @dev Negate a point in G1: (x, -y mod p).
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) {
            return G1Point(0, 0);
        }
        // y != 0 assumed valid; caller responsible for validation if needed

        return G1Point(p.x, FIELD_MODULUS - p.y);
    }
    function run(uint256[12] memory input) public view returns (bool) {
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 0x08, input, 0x0180, out, 0x20)
        }
        // revert("Wrong pairing");
        // return 0;
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }
    function run3(uint256[18] memory input) public view returns (bool) {
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 0x08, input, 0x0240, out, 0x20)
        }
        // revert("Wrong pairing");
        // return 0;
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }
    function pairing_check(
        G1Point memory P1,
        G2Point memory Q1,
        G1Point memory P2,
        G2Point memory Q2
        ) public view returns (bool){
        G1Point memory nP2 = negate(P2);
    
        uint256[12] memory points = [
            P1.x,
            P1.y,
            Q1.x[1],
            Q1.x[0],
            Q1.y[1],
            Q1.y[0],
            nP2.x,
            nP2.y,
            Q2.x[1],
            Q2.x[0],
            Q2.y[1],
            Q2.y[0]
        ];
        bool x = run(points);
        return x;
    }

    function pairing_check(
        G1Point memory P1,
        G2Point memory Q1,
        G1Point memory P2,
        G2Point memory Q2,
        G1Point memory P3,
        G2Point memory Q3
        ) public view returns (bool){
        G1Point memory nP3 = negate(P3);
    
        uint256[18] memory points = [
            P1.x,
            P1.y,
            Q1.x[1],
            Q1.x[0],
            Q1.y[1],
            Q1.y[0],
            P2.x,
            P2.y,
            Q2.x[1],
            Q2.x[0],
            Q2.y[1],
            Q2.y[0],
            nP3.x,
            nP3.y,
            Q3.x[1],
            Q3.x[0],
            Q3.y[1],
            Q3.y[0]
        ];
        bool x = run3(points);
        return x;
    }


    constructor() {}

    event HTLCETHNew(
        bytes32 indexed contractId,
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        uint256 hashlock,
        uint256 timelock
    );
    event HTLCETHWithdraw(bytes32 indexed contractId);
    event HTLCETHRefund(bytes32 indexed contractId);

    struct LockContract {
        address sender;
        address receiver;
        uint256 amount;
        uint256 hashlock;
        uint256 timelock; // locked UNTIL this time (in seconds since unix epoch)
        bool withdrawn;
        bool refunded;
        Preimage preimage;
    }

    mapping(bytes32 => LockContract) public contracts;

    modifier futureTimelock(uint256 _time) {
        require(_time > block.timestamp, "timelock must be in the future");
        _;
    }

    modifier contractExists(bytes32 _contractId) {
        require(haveContract(_contractId), "contractId does not exist");
        _;
    }

    modifier hashlockMatches(bytes32 _contractId, Preimage memory preimage) {
            //TODO: we should use param
            G1Point memory base = param.u0;
            for (uint32 i = 0; i < 40; ++i) {
                bool bitSet = (contracts[_contractId].hashlock & (1 << i)) != 0;
                if (bitSet) {
                    base = add(base, param.u_vec[i]);
                } 
            }
            // revert("fail");
            bool success = pairing_check(preimage.sk2, param.g2, param.g, preimage.sk3);
            if (!success == true){
                revert("Fail hashlock preimage check");
            }

            bool success2 = pairing_check(base, preimage.sk3, param.g1a, param.g2b, preimage.sk1, param.g2);
            if (!success2 == true){
                revert("Fail hashlock preimage check");
            }

        require(
            _contractId == _contractId
        );
        _;
    }

    modifier withdrawable(bytes32 _contractId) {
        LockContract memory c = contracts[_contractId];
        require(c.receiver == msg.sender, "not receiver");
        require(!c.withdrawn, "already withdrawn");
        // If you want to forbid withdraw after timelock, uncomment:
        // require(c.timelock > block.timestamp, "timelock passed");
        _;
    }

    modifier refundable(bytes32 _contractId) {
        LockContract memory c = contracts[_contractId];
        require(c.sender == msg.sender, "not sender");
        require(!c.refunded, "already refunded");
        require(!c.withdrawn, "already withdrawn");
        require(c.timelock <= block.timestamp, "timelock not yet passed");
        _;
    }

    /**
     * @dev Create a new HTLC by locking ETH in the contract.
     *
     * @param _receiver Receiver of the ETH.
     * @param _hashlock A int245 hash (hashlock/circuit id).
     * @param _timelock UNIX timestamp when the lock expires (seconds).
     * @return contractId The id of the new HTLC.
     */
    function newContract(
        address _receiver,
        uint256 _hashlock,
        uint256 _timelock
    )
        external
        payable
        futureTimelock(_timelock)
        returns (bytes32 contractId)
    {
        uint256 _amount = msg.value;
        // NOTE: set the amount to be the right amount. Here for testing purpose, we set anything >0
        require(_amount > 0, "amount must be > 0");
        require(_receiver != address(0), "receiver is zero address");

        contractId = sha256(
            abi.encodePacked(
                msg.sender,
                _receiver,
                _amount,
                _hashlock,
                _timelock
            )
        );

        // Prevent collision: require unique combination or different hashlock.
        require(!haveContract(contractId), "contract already exists");

        LockContract storage c = contracts[contractId];
        // Simple fields
        c.sender = msg.sender;
        c.receiver = _receiver;
        c.amount = _amount;
        c.hashlock = _hashlock;
        c.timelock = _timelock;
        c.withdrawn = false;
        c.refunded = false;
        
        // contracts[contractId] = LockContract({
        //     sender: msg.sender,
        //     receiver: _receiver,
        //     amount: _amount,
        //     hashlock: _hashlock,
        //     timelock: _timelock,
        //     withdrawn: false,
        //     refunded: false,
        //     preimage: preimage
        // });

        emit HTLCETHNew(
            contractId,
            msg.sender,
            _receiver,
            _amount,
            _hashlock,
            _timelock
        );
    }

    /**
     * @dev Receiver withdraws ETH using the correct preimage.
     *
     * @param _contractId The HTLC id.
     * @param _preimage The secret; sha256(_preimage) must equal hashlock.
     */
    function withdraw(
        bytes32 _contractId,
        Preimage memory _preimage
    )
        external
        contractExists(_contractId)
        hashlockMatches(_contractId, _preimage)
        withdrawable(_contractId)
        returns (bool)
    {
        LockContract memory c = contracts[_contractId];

        c.preimage = _preimage;
        c.withdrawn = true;

        // Effects before interaction
        (bool success, ) = c.receiver.call{value: c.amount}("");
        require(success, "ETH transfer failed");

        emit HTLCETHWithdraw(_contractId);
        return true;
    }

    /**
     * @dev Sender refunds ETH after timelock if not withdrawn.
     *
     * @param _contractId The HTLC id.
     */
    function refund(
        bytes32 _contractId
    )
        external
        contractExists(_contractId)
        refundable(_contractId)
        returns (bool)
    {
        LockContract memory c = contracts[_contractId];

        c.refunded = true;

        // Effects before interaction
        (bool success, ) = c.sender.call{value: c.amount}("");
        require(success, "ETH refund failed");

        emit HTLCETHRefund(_contractId);
        return true;
    }

    /**
     * @dev Read contract details.
     */
    function getContract(
        bytes32 _contractId
    )
        external
        view
        returns (
            address sender,
            address receiver,
            uint256 amount,
            uint256 hashlock,
            uint256 timelock,
            bool withdrawn,
            bool refunded,
            Preimage memory preimage
        )
    {
        require (haveContract(_contractId) == true);
        LockContract memory c = contracts[_contractId];
        return (
            c.sender,
            c.receiver,
            c.amount,
            c.hashlock,
            c.timelock,
            c.withdrawn,
            c.refunded,
            c.preimage
        );
    }

    /**
     * @dev Check existence.
     */
    function haveContract(
        bytes32 _contractId
    ) public view returns (bool exists) {
        return (contracts[_contractId].sender != address(0));
    }

    // function testpreimage(Preimage memory preimage) public view returns (G1Point memory){
    //     G1Point memory base = param.u0;
    //     for (uint32 i = 0; i < 40; ++i) {
    //         bool bitSet = (preimage.id & (1 << i)) != 0;
    //         if (bitSet) {
    //             base = add(base, preimage.u_vec[i]);
    //         } 
    //     }
    //     // revert("fail");
    //     bool success = pairing_check(preimage.sk2, preimage.g2, preimage.g, preimage.sk3);
    //     if (!success == true){
    //         revert("Fail preimage check");
    //     }

    //     bool success2 = pairing_check(base, preimage.sk3, preimage.g1a, preimage.g2b, preimage.sk1, preimage.g2);
    //     if (!success2 == true){
    //         revert("Fail preimage2 check");
    //     }

    //     return base;
    // }
}
