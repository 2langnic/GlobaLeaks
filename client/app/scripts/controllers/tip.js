GLClient.controller('TipCtrl', ['$scope', '$http', '$route', '$location', '$modal', 'Tip', 'ReceiverTips',
  function($scope, $http, $route, $location, $modal, Tip, ReceiverTips) {

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
  
  $scope.tip_access = function (id) {
    var modalInstance = $modal.open({
      templateUrl: 'views/partials/receiver_tip_password.html',
      controller: ReceiverTipPasswordControl,
      resolve: {
        tip_id: function () {
          return id;
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

  $scope.$watch('msg_receiver_selected', function(){
    if ($scope.msg_receiver_selected) {
      messageResource.query({receiver_id: $scope.msg_receiver_selected}, function(messageCollection){
        $scope.tip.messages = messageCollection;

        $scope.tip.messages.newMessage = function(content) {
          var m = new messageResource({receiver_id: $scope.msg_receiver_selected});
          m.content = content;
          m.$save(function(newMessage) {
            $scope.tip.messages.unshift(newMessage);
          });
        };

        // XXX perhaps make this return a lazyly instanced item.
        // look at $resource code for inspiration.
        fn($scope.tip);
      });
    }
  }, true);

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
      return $http({method: 'DELETE', url: '/rtip/' + tip_id, data:{global_delete: global_delete, extend:false}}).
                 success(function(data, status, headers, config){ 
                                                                  $location.url('/receiver/tips');
                                                                  $route.reload();
                                                                });
  };
}];

ReceiverTipPasswordControl = ['$scope', '$http', '$route', '$location', '$modalInstance', 'ReceiverSubmissionAuthentication', 'tip_id','doublepasswordWatcher',
                     function ($scope, $http, $route, $location, $modalInstance, ReceiverSubmissionAuthentication, tip_id, doublepasswordWatcher ) {
  
  doublepasswordWatcher($scope, "receiver_submission_key_new",
        "receiver_submission_key_check");
  $scope.tip_id = tip_id;
  
  $scope.ReceiverSubmissionAuthentication = ReceiverSubmissionAuthentication.get({tip_id:tip_id});
  //now the variable set_password is under $scope.ReceiverSubmissionAuthentication.password_set available
  //regarding defintion Tip_Authentication in rtip.py at the method get which returns password_set

  $scope.cancel = function () {
    $modalInstance.close();
  };

  $scope.ok = function (password) {
        if ($scope.ReceiverSubmissionAuthentication.password_set) {
            //encrypt all data with password and relocate to the location because a password was already set;
            $location.path("/status/"+tip_id);
        }
        else {
            $scope.ReceiverSubmissionAuthentication.password = password;
            $scope.ReceiverSubmissionAuthentication.$update({tip_id:tip_id})
            $location.path("/status/"+tip_id);
            // use the password to call the $update on  to call the put and wait
            //ReceiverSubmissionAuthentication.password = password
            //ReceiverSubmissionAuthentication.$update()
        }
      $modalInstance.close();
      //check the password
     // $location.path("/status/"+tip_id);
  };
}];

ModalPostponeTipCtrl = ['$scope', '$http', '$route', '$location', 'Tip', '$modalInstance', 'tip_id',
                        function ($scope, $http, $route, $location, Tip, $modalInstance, tip_id) {


  $scope.tip_id = tip_id;

  var TipID = {tip_id: $scope.tip_id};
  new Tip(TipID, function(tip){
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

