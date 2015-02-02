'use strict';

GLClient.controller('SymCryptCtrl', ['$http','$rootScope', '$scope', '$location',
    function ($http, $rootScope, $scope, $location) {
        var validSymKeyLength;
        $scope.encryptionKey = '';
        $scope.$watch("encryptionKey", function () {
            $scope.validSymKeyLength = $scope.encryptionKey.length === 32;
        });

        var wrongkey = false;
        $scope.checkEncryptionKey = function (encryptionKey) {
            $http.put('/admin/symmkey', {'key': encryptionKey})
                    .success(function (response) {
                        $scope.wrongkey = !response.key_set_successful;
                        if (response.key_set_successful) {
                            $rootScope.$broadcast("REFRESH");
                            $location.path("/");
                        }
                    }
                    );
        };
    }]);