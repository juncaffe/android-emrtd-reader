/*
 * Copyright 2026 JunCaffe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.juncaffe.epassport.app.ui.screen

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.navigation
import com.juncaffe.epassport.app.presentation.PassportViewModel

@Composable
fun AppNavHost(navController: NavHostController) {
    NavHost(
        navController = navController,
        startDestination = "scan"
    ) {
        navigation(route = "scan", startDestination = "secure_keypad") {
            composable("secure_keypad") { backStackEntry ->
                val parentEntry = remember(backStackEntry) {
                    navController.getBackStackEntry("scan")
                }
                val sharedViewModel: PassportViewModel = hiltViewModel(parentEntry)
                SecureKeypadScreen(navController, sharedViewModel)
            }
            composable("scanner") { backStackEntry ->
                val parentEntry = remember(backStackEntry) {
                    navController.getBackStackEntry("scan")
                }
                val sharedViewModel: PassportViewModel = hiltViewModel(parentEntry)
                ScannerScreen(navController, sharedViewModel = sharedViewModel)
            }
        }
    }
}