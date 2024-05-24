//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
                                                     @@@@@@@@@@@@@@             
                                                    @@@@@@@@@@@@@@@@@@(         
                                                   @@@@@@@@@@@@@@@@@@@@@        
                                                  @@@@@@@@@@@@@@@@@@@@@@@@      
                                                           #@@@@@@@@@@@@@@      
                                                               @@@@@@@@@@@@     
                            @@@@@@@@@@@@@@*                    @@@@@@@@@@@@     
                           @@@@@@@@@@@@@@@     @               @@@@@@@@@@@@     
                          @@@@@@@@@@@@@@@     @                @@@@@@@@@@@      
                         @@@@@@@@@@@@@@@     @@               @@@@@@@@@@@@      
                        @@@@@@@@@@@@@@@     #@@             @@@@@@@@@@@@/       
                        @@@@@@@@@@@@@@.     @@@@@@@@@@@@@@@@@@@@@@@@@@@         
                       @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@            
                      @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@             
                     @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@           
                    @@@@@@@@@@@@@@@     @@@@@&%%%%%%%%&&@@@@@@@@@@@@@@          
                    @@@@@@@@@@@@@@      @@@@@               @@@@@@@@@@@         
                   @@@@@@@@@@@@@@@     @@@@@                 @@@@@@@@@@@        
                  @@@@@@@@@@@@@@@     @@@@@@                 @@@@@@@@@@@        
                 @@@@@@@@@@@@@@@     @@@@@@@                 @@@@@@@@@@@        
                @@@@@@@@@@@@@@@     @@@@@@@                 @@@@@@@@@@@&        
                @@@@@@@@@@@@@@     *@@@@@@@               (@@@@@@@@@@@@         
               @@@@@@@@@@@@@@@     @@@@@@@@             @@@@@@@@@@@@@@          
              @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
             @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            
            @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              
           .@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 
           @@@@@@@@@@@@@@%     @@@@@@@@@@@@@@@@@@@@@@@@(                        
          @@@@@@@@@@@@@@@                                                       
         @@@@@@@@@@@@@@@                                                        
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                         
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                          
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&                                          
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                           
 
* @title CollateralizedPausableFlags
* @custom:version 1.0.0
* @author Limit Break, Inc.
* @description Collateralized Pausable Flags is an extension for contracts
*              that require features to be pausable in the event of potential
*              or actual threats without incurring a storage read overhead cost
*              during normal operations by using contract starting balance as
*              a signal for checking the paused state.
*
*              Using contract balance to enable checking paused state creates an
*              economic penalty for developers that deploy code that can be 
*              exploited as well as an economic incentive (recovery of collateral)
*              for them to mitigate the threat.
*
*              Developers implementing Collateralized Pausable Flags should consider
*              their risk mitigation strategy and ensure funds are readily available
*              for pausing if ever necessary by setting an appropriate threshold 
*              value and considering use of an escrow contract that can initiate the
*              pause with funds.
*
*              There is no restriction on the depositor as this can be easily 
*              circumvented through a `SELFDESTRUCT` opcode.
*
*              Developers must be aware of potential outflows from the contract that
*              could reduce collateral below the pausable check threshold and protect
*              against those methods when pausing is required.
*/
abstract contract CollateralizedPausableFlags {

    /// @dev Emitted when the pausable flags are updated
    event PausableFlagsUpdated(uint256 previousFlags, uint256 newFlags);

    /// @dev Thrown when an execution path requires a flag to not be paused but it is paused
    error CollateralizedPausableFlags__Paused();
    /// @dev Thrown when an executin path requires a flag to be paused but it is not paused
    error CollateralizedPausableFlags__NotPaused();
    /// @dev Thrown when a call to withdraw funds fails
    error CollateralizedPausableFlags__WithdrawFailed();

    /// @dev Immutable variable that defines the native funds threshold before flags are checked
    uint256 private immutable nativeValueToCheckPauseState;
    /// @dev Flags for current pausable state, each bit is considered a separate flag
    uint256 private pausableFlags;

    /// @dev Immutable pointer for the _requireNotPaused function to use based on value threshold
    function(uint256) internal view immutable _requireNotPaused;
    /// @dev Immutable pointer for the _requirePaused function to use based on value threshold
    function(uint256) internal view immutable _requirePaused;
    /// @dev Immutable pointer for the _getPausableFlags function to use based on value threshold
    function() internal view returns (uint256) immutable _getPausableFlags;

    constructor(uint256 _nativeValueToCheckPauseState) {
        // Optimizes value check at runtime by reducing the stored immutable 
        // value by 1 so that greater than can be used instead of greater 
        // than or equal while allowing the deployment parameter to reflect 
        // the value at which the deployer wants to trigger pause checking.
        // Example: 
        //     Constructed with a value of 1000
        //     Immutable value stored is 999
        //     State checking enabled at 1000 units deposited because
        //     1000 > 999 evaluates true
        if (_nativeValueToCheckPauseState > 0) {
            unchecked {
                _nativeValueToCheckPauseState -= 1;
            }
            _requireNotPaused = _requireNotPausedWithCollateralCheck;
            _requirePaused = _requirePausedWithCollateralCheck;
            _getPausableFlags = _getPausableFlagsWithCollateralCheck;
        } else {
            _requireNotPaused = _requireNotPausedWithoutCollateralCheck;
            _requirePaused = _requirePausedWithoutCollateralCheck;
            _getPausableFlags = _getPausableFlagsWithoutCollateralCheck;
        }

        nativeValueToCheckPauseState = _nativeValueToCheckPauseState;
    }

    /**
     * @dev  Modifier to make a function callable only when the specified flags are not paused
     * @dev  Throws when any of the flags specified are paused
     * 
     * @param _flags  The flags to check for pause state
     */
    modifier whenNotPaused(uint256 _flags) {
        _requireNotPaused(_flags);
        _;
    }

    /**
     * @dev  Modifier to make a function callable only when the specified flags are paused
     * @dev  Throws when any of the flags specified are not paused
     * 
     * @param _flags  The flags to check for pause state
     */
    modifier whenPaused(uint256 _flags) {
        _requirePaused(_flags);
        _;
    }

    /**
     * @dev  Modifier to make a function callable only by a permissioned account
     * @dev  Throws when the caller does not have permission
     */
    modifier onlyPausePermissionedCaller() {
        _requireCallerHasPausePermissions();
        _;
    }

    /**
     * @notice  Updates the pausable flags settings
     * 
     * @dev     Throws when the caller does not have permission
     * @dev     **NOTE:** Pausable flag settings will only take effect if contract balance exceeds 
     * @dev     `nativeValueToPause`
     * 
     * @dev     <h4>Postconditions:</h4>
     * @dev     1. address(this).balance increases by msg.value
     * @dev     2. `pausableFlags` is set to the new value
     * @dev     3. Emits a PausableFlagsUpdated event
     * 
     * @param _pausableFlags  The new pausable flags to set
     */
    function pause(uint256 _pausableFlags) external payable onlyPausePermissionedCaller {
        _setPausableFlags(_pausableFlags);
    }

    /**
     * @notice  Allows any account to supply funds for enabling the pausable checks
     * 
     * @dev     **NOTE:** The threshold check for pausable collateral does not pause
     * @dev     any functions unless the associated pausable flag is set.
     */
    function pausableDepositCollateral() external payable {
        // thank you for your contribution to safety
    }

    /**
     * @notice  Resets all pausable flags to unpaused and withdraws funds
     * 
     * @dev     Throws when the caller does not have permission
     * 
     * @dev     <h4>Postconditions:</h4>
     * @dev     1. `pausableFlags` is set to zero
     * @dev     2. Emits a PausableFlagsUpdated event
     * @dev     3. Transfers `withdrawAmount` of native funds to `withdrawTo` if non-zero
     * 
     * @param withdrawTo      The address to withdraw the collateral to
     * @param withdrawAmount  The amount of collateral to withdraw
     */
    function unpause(address withdrawTo, uint256 withdrawAmount) external onlyPausePermissionedCaller {
        _setPausableFlags(0);

        if (withdrawAmount > 0) {
            (bool success, ) = withdrawTo.call{value: withdrawAmount}("");
            if(!success) revert CollateralizedPausableFlags__WithdrawFailed();
        }
    }

    /**
     * @notice  Returns collateralized pausable configuration information
     * 
     * @return _nativeValueToCheckPauseState  The collateral required to enable pause state checking
     * @return _pausableFlags                 The current pausable flags set, only checked when collateral met
     */
    function pausableConfigurationSettings() external view returns(
        uint256 _nativeValueToCheckPauseState, 
        uint256 _pausableFlags
    ) {
        unchecked {
            _nativeValueToCheckPauseState = nativeValueToCheckPauseState + 1;
            _pausableFlags = pausableFlags;
        }
    }

    /**
     * @notice  Updates the `pausableFlags` variable and emits a PausableFlagsUpdated event
     * 
     * @param _pausableFlags  The new pausable flags to set
     */
    function _setPausableFlags(uint256 _pausableFlags) internal {
        uint256 previousFlags = pausableFlags;

        pausableFlags = _pausableFlags;

        emit PausableFlagsUpdated(previousFlags, _pausableFlags);
    }

    /**
     * @notice  Checks the current pause state of the supplied flags and reverts if any are paused
     * 
     * @dev     *Should* be called prior to any transfers of native funds out of the contract for efficiency
     * @dev     Throws when the native funds balance is greater than the value to enable pausing AND
     * @dev     one or more of the supplied `_flags` is paused.
     * 
     * @param _flags  The flags to check for pause state
     */
    function _requireNotPausedWithCollateralCheck(uint256 _flags) private view {
        if (_nativeBalanceSubMsgValue() > nativeValueToCheckPauseState) {
            if (pausableFlags & _flags > 0) {
                revert CollateralizedPausableFlags__Paused();
            }
        }
    }

    /**
     * @notice  Checks the current pause state of the supplied flags and reverts if any are paused
     * 
     * @dev     Throws when one or more of the supplied `_flags` is paused.
     * 
     * @param _flags  The flags to check for pause state
     */
    function _requireNotPausedWithoutCollateralCheck(uint256 _flags) private view {
        if (pausableFlags & _flags > 0) {
            revert CollateralizedPausableFlags__Paused();
        }
    }

    /**
     * @notice  Checks the current pause state of the supplied flags and reverts if none are paused
     * 
     * @dev     *Should* be called prior to any transfers of native funds out of the contract for efficiency
     * @dev     Throws when the native funds balance is not greater than the value to enable pausing OR
     * @dev     none of the supplied `_flags` are paused.
     * 
     * @param _flags  The flags to check for pause state
     */
    function _requirePausedWithCollateralCheck(uint256 _flags) private view {
        if (_nativeBalanceSubMsgValue() <= nativeValueToCheckPauseState) {
            revert CollateralizedPausableFlags__NotPaused();
        } else if (pausableFlags & _flags == 0) {
            revert CollateralizedPausableFlags__NotPaused();
        }
    }

    /**
     * @notice  Checks the current pause state of the supplied flags and reverts if none are paused
     * 
     * @dev     Throws when none of the supplied `_flags` are paused.
     * 
     * @param _flags  The flags to check for pause state
     */
    function _requirePausedWithoutCollateralCheck(uint256 _flags) private view {
        if (pausableFlags & _flags == 0) {
            revert CollateralizedPausableFlags__NotPaused();
        }
    }

    /**
     * @notice  Returns the current state of the pausable flags
     * 
     * @dev     Will return zero if the native funds balance is not greater than the value to enable pausing
     * 
     * @return _pausableFlags  The current state of the pausable flags
     */
    function _getPausableFlagsWithCollateralCheck() private view returns(uint256 _pausableFlags) {
        if (_nativeBalanceSubMsgValue() > nativeValueToCheckPauseState) {
            _pausableFlags = pausableFlags;
        }
    }

    /**
     * @notice  Returns the current state of the pausable flags
     * 
     * @return _pausableFlags  The current state of the pausable flags
     */
    function _getPausableFlagsWithoutCollateralCheck() private view returns(uint256 _pausableFlags) {
        _pausableFlags = pausableFlags;
    }

    /**
     * @notice  Returns the current contract balance minus the value sent with the call
     * 
     * @dev     This is expected to be the contract balance at the beginning of a function call
     * @dev     to efficiently determine whether a contract has the necessary collateral to enable
     * @dev     the pausable flags checking for contracts that hold native token funds.
     * @dev     This should **NOT** be used in any way to determine current balance for contract logic
     * @dev     other than its intended purpose for pause state checking activation.
     */
    function _nativeBalanceSubMsgValue() private view returns (uint256 _value) {
        unchecked {
            _value = address(this).balance - msg.value;
        }
    }

    /**
     * @dev  To be implemented by an inheriting contract for authorization to `pause` and `unpause` 
     * @dev  functions as well as any functions in the inheriting contract that utilize the
     * @dev  `onlyPausePermissionedCaller` modifier.
     * 
     * @dev  Implementing contract function **MUST** throw when the caller is not permissioned
     */
    function _requireCallerHasPausePermissions() internal view virtual;
}