// SPDX-License-Identifier: MIT
pragma solidity >=0.8.2 <0.9.0;

contract Loterie {
    address public owner;
    uint public randNonce = 0;
    address[] public participants;
    uint public ticketPrice = 1 ether;

    constructor() {
        owner = msg.sender;
    }

    function participer() public payable {
        require(
            msg.sender != owner,
            "le propritaire n'a pas le droit de participer a la loterie"
        );
        require(msg.value == ticketPrice, "TIP; le prix du ticket est 1 ether");

        participants.push(msg.sender);
    }

    function random(uint _modulus) private returns (uint) {
        randNonce++; // Variable d’état à déclarer et initialiser à 0
        return
            uint(
                keccak256(
                    abi.encodePacked(block.timestamp, msg.sender, randNonce)
                )
            ) % _modulus;
    }

    function tirage() public {
        require(
            msg.sender == owner,
            "Seul le proprietaire peut faire le tirage"
        );
        require(participants.length >= 3, "Il faut plus de participants");
        uint indexGagne = random(participants.length);
        address gagnant = participants[indexGagne];
        payable(gagnant).transfer(address(this).balance);
        delete participants;
    }

    // Consulter le solde du contrat
    function getSolde() public view returns (uint) {
        return address(this).balance;
    }
}
