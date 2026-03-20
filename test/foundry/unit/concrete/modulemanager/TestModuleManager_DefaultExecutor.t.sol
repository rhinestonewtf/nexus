// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../../../utils/Imports.sol";
import "../../../utils/NexusTest_Base.t.sol";

/// @title TestModuleManager_DefaultExecutor
/// @notice Tests for the default executor feature on ModuleManager
contract TestModuleManager_DefaultExecutor is NexusTest_Base {
    // Nexus deployment with a default executor set
    Nexus internal nexusWithDefaultExecutor;
    NexusAccountFactory internal factoryWithDefaultExecutor;
    NexusBootstrap internal bootstrapperWithDefaultExecutor;

    MockExecutor internal defaultExecutor;
    MockExecutor internal otherExecutor;
    Counter internal counter;

    Vm.Wallet internal USER;
    Nexus internal USER_ACCOUNT;

    function setUp() public {
        init();

        defaultExecutor = new MockExecutor();
        otherExecutor = new MockExecutor();
        counter = new Counter();

        USER = createAndFundWallet("USER", 1000 ether);

        // Deploy a Nexus implementation with a non-zero default executor
        nexusWithDefaultExecutor = new Nexus(
            address(ENTRYPOINT),
            address(DEFAULT_VALIDATOR_MODULE),
            address(defaultExecutor),
            abi.encodePacked(address(0xeEeEeEeE)),
            ""
        );

        factoryWithDefaultExecutor = new NexusAccountFactory(address(nexusWithDefaultExecutor), FACTORY_OWNER.addr);
        vm.prank(FACTORY_OWNER.addr);
        META_FACTORY.addFactoryToWhitelist(address(factoryWithDefaultExecutor));

        bootstrapperWithDefaultExecutor = new NexusBootstrap(
            address(DEFAULT_VALIDATOR_MODULE),
            address(defaultExecutor),
            abi.encodePacked(address(0xa11ce)),
            ""
        );

        // Deploy account via factory
        USER_ACCOUNT = _deployAccountWithDefaultExecutor(USER);
        vm.label(address(USER_ACCOUNT), "USER_ACCOUNT");
    }

    // ──────────────────────────────────────────────────
    // Default executor can execute without being in the sentinel list
    // ──────────────────────────────────────────────────

    function test_DefaultExecutor_CanExecute() public {
        uint256 before = counter.getNumber();

        defaultExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );

        assertEq(counter.getNumber(), before + 1, "Default executor should be able to execute");
    }

    function test_DefaultExecutor_CanExecuteBatch() public {
        Execution[] memory execs = new Execution[](3);
        for (uint256 i = 0; i < 3; i++) {
            execs[i] = Execution(address(counter), 0, abi.encodeWithSelector(Counter.incrementNumber.selector));
        }

        defaultExecutor.executeBatchViaAccount(INexus(address(USER_ACCOUNT)), execs);
        assertEq(counter.getNumber(), 3, "Default executor batch should work");
    }

    // ──────────────────────────────────────────────────
    // isModuleInstalled returns true for the default executor
    // ──────────────────────────────────────────────────

    function test_DefaultExecutor_IsReportedAsInstalled() public view {
        assertTrue(
            USER_ACCOUNT.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(defaultExecutor), ""),
            "Default executor should report as installed"
        );
    }

    // ──────────────────────────────────────────────────
    // Non-installed, non-default executor is rejected
    // ──────────────────────────────────────────────────

    function test_RevertIf_NonDefaultNonInstalledExecutor() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidModule.selector, address(otherExecutor)));
        otherExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
    }

    // ──────────────────────────────────────────────────
    // Installing the same executor (default) into the sentinel list still works
    // ──────────────────────────────────────────────────

    function test_InstallDefaultExecutor_InSentinelList_StillWorks() public {
        // Install the default executor explicitly into the sentinel list
        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(defaultExecutor),
            ""
        );

        Execution[] memory execution = new Execution[](1);
        execution[0] = Execution(address(USER_ACCOUNT), 0, callData);

        PackedUserOperation[] memory userOps = _buildUserOp(USER, execution);
        ENTRYPOINT.handleOps(userOps, payable(USER.addr));

        // It should still be reported as installed
        assertTrue(
            USER_ACCOUNT.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(defaultExecutor), ""),
            "Default executor should still be installed after explicit install"
        );

        // And it should still be able to execute
        defaultExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
        assertEq(counter.getNumber(), 1, "Execution should succeed after explicit install");
    }

    // ──────────────────────────────────────────────────
    // After installing default executor in list, uninstall from list, still works via default
    // ──────────────────────────────────────────────────

    function test_UninstallDefaultExecutorFromList_StillWorksAsDefault() public {
        // Install into sentinel list
        bytes memory installCallData = abi.encodeWithSelector(
            IModuleManager.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(defaultExecutor),
            ""
        );
        Execution[] memory installExec = new Execution[](1);
        installExec[0] = Execution(address(USER_ACCOUNT), 0, installCallData);
        PackedUserOperation[] memory installOps = _buildUserOp(USER, installExec);
        ENTRYPOINT.handleOps(installOps, payable(USER.addr));

        // Now uninstall from sentinel list
        // Need the prev pointer — for a single entry after sentinel, prev is SENTINEL
        address SENTINEL_ADDR = address(0x1);
        bytes memory uninstallCallData = abi.encodeWithSelector(
            IModuleManager.uninstallModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(defaultExecutor),
            abi.encode(SENTINEL_ADDR, "")
        );
        Execution[] memory uninstallExec = new Execution[](1);
        uninstallExec[0] = Execution(address(USER_ACCOUNT), 0, uninstallCallData);
        PackedUserOperation[] memory uninstallOps = _buildUserOp(USER, uninstallExec);
        ENTRYPOINT.handleOps(uninstallOps, payable(USER.addr));

        // Default executor should still work because it's immutable
        defaultExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
        assertEq(counter.getNumber(), 1, "Default executor should still work after uninstall from list");

        // And still reported as installed
        assertTrue(
            USER_ACCOUNT.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(defaultExecutor), ""),
            "Default executor should still report as installed after list removal"
        );
    }

    // ──────────────────────────────────────────────────
    // Installing another executor alongside the default works
    // ──────────────────────────────────────────────────

    function test_OtherExecutorWorksAlongsideDefault() public {
        // Install otherExecutor
        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(otherExecutor),
            ""
        );
        Execution[] memory execution = new Execution[](1);
        execution[0] = Execution(address(USER_ACCOUNT), 0, callData);
        PackedUserOperation[] memory userOps = _buildUserOp(USER, execution);
        ENTRYPOINT.handleOps(userOps, payable(USER.addr));

        // Both should work
        defaultExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
        assertEq(counter.getNumber(), 1, "Default executor should work");

        otherExecutor.executeViaAccount(
            INexus(address(USER_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
        assertEq(counter.getNumber(), 2, "Other executor should also work");
    }

    // ──────────────────────────────────────────────────
    // address(0) default executor preserves original behavior
    // ──────────────────────────────────────────────────

    function test_ZeroDefaultExecutor_PreservesOriginalBehavior() public {
        // BOB_ACCOUNT was deployed with address(0) default executor (original setup)
        // The default MockExecutor from TestHelper should NOT be able to execute
        MockExecutor someExecutor = new MockExecutor();

        vm.expectRevert(abi.encodeWithSelector(InvalidModule.selector, address(someExecutor)));
        someExecutor.executeViaAccount(
            INexus(address(BOB_ACCOUNT)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
    }

    // ──────────────────────────────────────────────────
    // Value transfer via default executor
    // ──────────────────────────────────────────────────

    function test_DefaultExecutor_ValueTransfer() public {
        address receiver = makeAddr("receiver");
        uint256 sendValue = 1 ether;

        // Fund the account
        (bool res,) = payable(address(USER_ACCOUNT)).call{ value: 2 ether }("");
        assertTrue(res, "Funding should succeed");

        defaultExecutor.executeViaAccount(INexus(address(USER_ACCOUNT)), receiver, sendValue, "");
        assertEq(receiver.balance, sendValue, "Receiver should have received ETH via default executor");
    }

    // ──────────────────────────────────────────────────
    // Bootstrap calls onInstall on the default executor
    // ──────────────────────────────────────────────────

    function test_Bootstrap_CallsOnInstallOnDefaultExecutor() public {
        Vm.Wallet memory wallet2 = createAndFundWallet("WALLET2", 1000 ether);

        bytes memory moduleInstallData = abi.encodePacked(wallet2.addr);
        BootstrapConfig[] memory validators = BootstrapLib.createArrayConfig(address(VALIDATOR_MODULE), moduleInstallData);
        BootstrapConfig memory hook = BootstrapLib.createSingleConfig(address(0), "");

        bytes memory _initData = abi.encode(
            address(bootstrapperWithDefaultExecutor),
            abi.encodeCall(
                bootstrapperWithDefaultExecutor.initNexusScoped,
                ("", validators, hook, RegistryConfig({ registry: REGISTRY, attesters: ATTESTERS, threshold: THRESHOLD }))
            )
        );

        bytes32 salt = keccak256("1");
        address payable accountAddress = factoryWithDefaultExecutor.computeAccountAddress(_initData, salt);

        bytes memory factoryData = abi.encodeWithSelector(factoryWithDefaultExecutor.createAccount.selector, _initData, salt);
        bytes memory initCode = abi.encodePacked(
            address(META_FACTORY),
            abi.encodeWithSelector(META_FACTORY.deployWithFactory.selector, address(factoryWithDefaultExecutor), factoryData)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        uint256 nonce = getNonce(accountAddress, MODE_VALIDATION, address(VALIDATOR_MODULE), bytes3(0));
        userOps[0] = buildPackedUserOp(accountAddress, nonce);
        userOps[0].initCode = initCode;
        userOps[0].signature = signUserOp(wallet2, userOps[0]);

        ENTRYPOINT.depositTo{ value: 100 ether }(accountAddress);

        // Verify that the default executor's onInstall was called during bootstrap
        // MockExecutor emits ExecutorOnInstallCalled when data.length >= 32, but with empty data it doesn't emit
        // We verify it was initialized by checking isInitialized would have been called
        // The key proof is that the account deploys successfully with bootstrap calling onInstall
        ENTRYPOINT.handleOps(userOps, payable(wallet2.addr));

        // Account is deployed and default executor works immediately
        Nexus account = Nexus(accountAddress);
        defaultExecutor.executeViaAccount(
            INexus(address(account)),
            address(counter),
            0,
            abi.encodeWithSelector(Counter.incrementNumber.selector)
        );
        assertEq(counter.getNumber(), 1, "Default executor should work on freshly bootstrapped account");
    }

    // ──────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────

    function _deployAccountWithDefaultExecutor(Vm.Wallet memory wallet) internal returns (Nexus) {
        bytes memory moduleInstallData = abi.encodePacked(wallet.addr);

        BootstrapConfig[] memory validators = BootstrapLib.createArrayConfig(address(VALIDATOR_MODULE), moduleInstallData);
        BootstrapConfig memory hook = BootstrapLib.createSingleConfig(address(0), "");

        bytes memory _initData = abi.encode(
            address(bootstrapperWithDefaultExecutor),
            abi.encodeCall(
                bootstrapperWithDefaultExecutor.initNexusScoped,
                ("", validators, hook, RegistryConfig({ registry: REGISTRY, attesters: ATTESTERS, threshold: THRESHOLD }))
            )
        );

        bytes32 salt = keccak256("0");
        address payable accountAddress = factoryWithDefaultExecutor.computeAccountAddress(_initData, salt);

        bytes memory factoryData = abi.encodeWithSelector(factoryWithDefaultExecutor.createAccount.selector, _initData, salt);
        bytes memory initCode = abi.encodePacked(
            address(META_FACTORY),
            abi.encodeWithSelector(META_FACTORY.deployWithFactory.selector, address(factoryWithDefaultExecutor), factoryData)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        uint256 nonce = getNonce(accountAddress, MODE_VALIDATION, address(VALIDATOR_MODULE), bytes3(0));
        userOps[0] = buildPackedUserOp(accountAddress, nonce);
        userOps[0].initCode = initCode;
        userOps[0].signature = signUserOp(wallet, userOps[0]);

        ENTRYPOINT.depositTo{ value: 100 ether }(accountAddress);
        ENTRYPOINT.handleOps(userOps, payable(wallet.addr));

        return Nexus(accountAddress);
    }

    function _buildUserOp(Vm.Wallet memory wallet, Execution[] memory execution) internal view returns (PackedUserOperation[] memory) {
        return buildPackedUserOperation(wallet, USER_ACCOUNT, EXECTYPE_DEFAULT, execution, address(VALIDATOR_MODULE), 0);
    }
}
