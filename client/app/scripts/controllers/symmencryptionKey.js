'use strict';

GLClient.controller('SymCryptCtrl', ['$http','$rootScope', 'Node', '$scope', '$location',
    function ($http, $rootScope, Node, $scope, $location) {
        
        
        var changeResult;
        var validSymKeyLength;
        var validNewSymKeyLength;
        var correct_key = false;
        var changeClicked = false;
        var changeEncryptionclicked = false;
        var clickedCheckEncryptionKey = false; 
        
        
        $scope.encryptionKey = '';
        $scope.$watch("encryptionKey", function () {
            $scope.validSymKeyLength = $scope.encryptionKey.length === 32;
            $scope.correct_key = false;
        });
        
      
        $scope.new_encryptionKey = '';
        $scope.$watch("new_encryptionKey", function () {
            $scope.validNewSymKeyLength = $scope.new_encryptionKey.length === 32;
        });

        
        $scope.checkEncryptionKey = function (encryptionKey) {
            $http.put('/admin/symmkey', {'key': encryptionKey})
                    .success(function (response) {
                        if (response.key_set_successful) {
                            $rootScope.$broadcast("REFRESH");
                            $location.path("/");
                        } else {
                           $scope.clickedCheckEncryptionKey = true;
                           $scope.correct_key = response.key_set_successful; 
                        }
                    }
                    );
        };
        
        
        $scope.checkforChangeEncryptionKey = function (encryptionKey) {
            $http.post('/admin/symmkey', {'key': encryptionKey,
                                           'newKey': "",
                                           'check': true
                                       })
                    .success(function (response) {
                        $scope.correct_key = response.key_check_successful;
                    }
                    );
        };
       
        /*
         * This function call the post of the symmkey implementation and tries to change the 
         * symmetric encryption key
         */
        $scope.changeEncryptionKey = function (encryptionKey,new_encryptionKey) {
            $scope.changeClicked = true;
            $http.post('/admin/symmkey', {'key': encryptionKey,
                                           'newKey': new_encryptionKey,
                                            'check':false})
                    .success(function (response) {
                        $scope.changeClicked = false;
                        $scope.changeResult = response.key_change_successful;
                        $scope.changeEncryptionclicked = true;
                    }
                    );
        };
    }]);