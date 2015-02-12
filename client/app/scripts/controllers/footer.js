'use strict';

GLClient.controller('FooterCtrl', ['$scope', '$location', '$modal',
    function ($scope, $location, $modal) {

        var contacts = {path: '/static/footer_contacts.html',
            name: 'Contacts'};

        var imprint =
                {path: '/static/footer_imprint.html',
                    name: 'Imprint'};

        var dataProtectionNotice =
                {path: '/static/footer_dataProtectionNotice.html',
                    name: 'DataProtectionNotice'};

        var legalNotice =
                {path: '/static/footer_legalNotice.html',
                    name: 'LegalNotice'};

        var open = function (show) {
            $scope.current_show = show.path;
            var windowclass = 'mainFooter-dialog-' + show.name;
            var modalInstance = $modal.open({
                templateUrl: 'views/partials/modalMainTemplate.html',
                controller: 'ModalMainDialogControl',
                windowClass: windowclass,
                size: 'lg',
                scope: $scope
            });
        };

        showContacts = function () {
            open(contacts);
        };

        showImprint = function () {
            open(imprint);
        };

        showDataProtectionNotice = function () {
            open(dataProtectionNotice);
        };

        showLegalNotice = function () {
            open(legalNotice);
        };
    }]);


GLClient.controller('ModalMainDialogControl', ['$scope', '$modalInstance', '$location',
    function ($scope, $modalInstance, $location) {

        $scope.cancel = function () {
            $modalInstance.close();
        };

    }]);
