GLClient.controller('TipCtrl', ['$scope', '$http', '$route', '$location', '$modal', 'Tip', 'ReceiverTips', 'Receivers', 'ReceiverPreferences',
    function ($scope, $http, $route, $location, $modal, Tip, ReceiverTips, Receivers,ReceiverPreferences) {

        $scope.receivers = Receivers.query();
        $scope.receiverPreferences = ReceiverPreferences.get();

        $scope.tip_delete = function (id, global_delete) {
            $scope.tip_id = id;
            $scope.global_delete = global_delete;
            var modalInstance = $modal.open({
                templateUrl: 'views/partials/tip_delete.html',
                controller: ModalDeleteTipCtrl,
                resolve: {
                    tip_id: function () {
                        return $scope.tip_id;
                    },
                    global_delete: function () {
                        return $scope.global_delete;
                    }
                }
            });
        };

        $scope.tip_extend = function (id) {
            $scope.tip_id = id;

            var modalInstance = $modal.open({
                templateUrl: 'views/partials/tip_extend.html',
                controller: ModalPostponeTipCtrl,
                resolve: {
                    tip_id: function () {
                        return $scope.tip_id;
                    }
                }
            });

        };
        $scope.addReceiver = function (allreceiver) {
            // Call the api of the backend
            // Refresh the tip.receiverlist
            $http.post('/rtip/' + $scope.tip.id + '/receiverConfig', {'action': "add",
                'receiverID': allreceiver.id
            }).success(function (response) {
                $scope.tip.receivers = response;
            }
            );
            console.log("Add:" + allreceiver.name);
        };

        $scope.removeReceiver = function (allreceiver) {
            if ($scope.tip.receiver_id === allreceiver.id) {
                $location.url('/receiver/tips')
                console.log("Removed self from tip")
            };
            
            $http.post('/rtip/' + $scope.tip.id + '/receiverConfig', {'action': "remove",
                'receiverID': allreceiver.id
            }).success(function (response) {

                $scope.tip.receivers = response;
            }
            );
            console.log("Remove:" + allreceiver.name);
        };

    }]);

GLClient.controller('TipWBCtrl', ['$scope', '$http', '$route', '$location', '$modal', 'Tip', 'ReceiverTips', '$rootScope',
    function ($scope, $http, $route, $location, $modal, Tip, ReceiverTips, $rootScope) {
   }]);

ModalDeleteTipCtrl = ['$scope', '$http', '$route', '$location', '$modalInstance', 'tip_id', 'global_delete',
    function ($scope, $http, $route, $location, $modalInstance, tip_id, global_delete) {

        $scope.tip_id = tip_id;
        $scope.global_delete = global_delete;

        $scope.cancel = function () {
            $modalInstance.close();
        };

        $scope.ok = function () {
            $modalInstance.close();
            return $http({method: 'DELETE', url: '/rtip/' + tip_id, data: {global_delete: global_delete, extend: false}}).
                    success(function (data, status, headers, config) {
                        $location.url('/receiver/tips');
                        $route.reload();
                    });
        };
    }];

ModalPostponeTipCtrl = ['$scope', '$http', '$route', '$location', 'Tip', '$modalInstance', 'tip_id',
    function ($scope, $http, $route, $location, Tip, $modalInstance, tip_id) {


        $scope.tip_id = tip_id;

        var TipID = {tip_id: $scope.tip_id};
        new Tip(TipID, function (tip) {
            $scope.tip = tip;
        });

        $scope.cancel = function () {
            $modalInstance.close();
        };

        $scope.ok = function () {
            $modalInstance.close();

            $scope.tip.extend = true;

            $scope.tip.$update();
            $route.reload();
        };

    }];

