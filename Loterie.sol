// SPDX-License-Identifier: MIT
pragma solidity >=0.8.2 <0.9.0;

contract Loterie {
    address public owner;
    uint public randNonce = 0;
    address[] public participants;
    uint public ticketPrice = 0.1 ether;
    address public lastWinner;

    event Winner(address indexed winner, uint prize, uint ownerFee);

    constructor() {
        owner = msg.sender;
    }

    function participer() public payable {
        require(
            msg.sender != owner,
            "le propritaire n'a pas le droit de participer a la loterie"
        );
        require(msg.value == ticketPrice, "TIP; le prix du ticket est 0.1 ether");

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
        
        //calculer 10% pour le proprietaire et 90% pour le gagnant
        uint totalBalance = address(this).balance;
        uint ownerFee = (totalBalance * 10) / 100;
        uint winnerPrize = totalBalance - ownerFee;
        
        //pour transferer les fonds
        payable(owner).transfer(ownerFee);
        payable(gagnant).transfer(winnerPrize);
        
        //stocker le gagnant et émettre un événement
        lastWinner = gagnant;
        emit Winner(gagnant, winnerPrize, ownerFee);
        
        delete participants;
    }

    // Consulter le solde du contrat
    function getSolde() public view returns (uint) {
        return address(this).balance;
    }
}
