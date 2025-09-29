'use strict'

angular.module('cf')
    .controller('APIInfoModalCtrl', ['$scope', '$rootScope', '$modalInstance', '$http', 'testContext', 'message', 'contextType', 'useHttp', 'Notification', 
        function($scope, $rootScope, $modalInstance, $http, testContext, message, contextType, useHttp, Notification) {
            
            $scope.apiInfo = {
                endpoint: $rootScope.appInfo.url +'/api/hl7v2/testcontext/'+ testContext.id+'/validateMessage' || '',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                parameters: {
                    contextType: contextType,
                    useHttp: useHttp                                      
                }
            };

            // Initialize parameters from test context
            if (testContext.parameters) {
                $scope.apiInfo.parameters = angular.copy(testContext.parameters);
            }

            // If there's a message, include it in the parameters
            if (message) {
                $scope.apiInfo.parameters.content = message.content;
            }

            // Helper function to check if a value is an object
            $scope.isObject = function(value) {
                return value !== null && typeof value === 'object' && !Array.isArray(value);
            };

            // Test the API endpoint
            $scope.testEndpoint = function() {
                if (!$scope.apiInfo.endpoint) {
                    Notification.error('Endpoint URL is required');
                    return;
                }

                var config = {
                    method: $scope.apiInfo.method,
                    url: $scope.apiInfo.endpoint,
                    headers: $scope.apiInfo.headers,
                    data: $scope.apiInfo.parameters
                };

                $scope.testing = true;
                $http(config)
                    .then(function(response) {
                        $scope.testResult = {
                            status: response.status,
                            headers: response.headers(),
                            data: response.data
                        };
                        Notification.success('API test successful');
                    })
                    .catch(function(error) {
                        $scope.testResult = {
                            status: error.status,
                            statusText: error.statusText,
                            data: error.data
                        };
                        Notification.error('API test failed: ' + (error.statusText || 'Unknown error'));
                    })
                    .finally(function() {
                        $scope.testing = false;
                    });
            };

            // Update the generateCurlCommand function to update the curlCommand
            $scope.updateCurlCommand = function () {
                var headers = [];
                var params = JSON.stringify($scope.apiInfo.parameters, null, 2);

                // Format headers for curl
                for (var key in $scope.apiInfo.headers) {
                    if ($scope.apiInfo.headers.hasOwnProperty(key)) {
                        headers.push("--header '" + key + ": " + $scope.apiInfo.headers[key] + "'");
                    }
                }
                if ($scope.apiInfo.authtoken) {
                    headers.push("--header 'Authorization: Basic " + $scope.apiInfo.authtoken + "'");
                }

                $scope.curlCommand = "curl -X " + $scope.apiInfo.method + " \\\n" +
                    headers.join(" \\\n") + " \\\n" +
                    "-d '" + params.replace(/'/g, "'\\''") + "' \\\n" +
                    "'" + $scope.apiInfo.endpoint + "'";
            };

            // Watch for changes to update the curl command
            $scope.$watch('apiInfo', function () {
                $scope.updateCurlCommand();
            }, true);

            // Initial update
            $scope.updateCurlCommand();

            // Close the modal
            $scope.close = function() {
                $modalInstance.dismiss('cancel');
            };            
        }]);
