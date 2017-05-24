       
function getCurrentTabUrl(callback) {
  var queryInfo = {
    active: true,
    currentWindow: true
  };

  chrome.tabs.query(queryInfo, function(tabs) {
    var tab = tabs[0];
    var url = tab.url;
    var title = tab.title;
    console.assert(typeof url == 'string', 'tab.url should be a string');
    callback(url,title);
  });

}

function saveArticle(url, callback, errorCallback) {
  var baseUrl = 'https://localhost:8081/api/post/1';
  var x = new XMLHttpRequest();
  x.open('POST', baseUrl);
  x.responseType = 'json';
  x.setRequestHeader("Content-Type", "application/json");
  x.setRequestHeader("Accept","*/*");
  x.onload = function() {
    var response = x.response;
    console.log(response);
    if (!response) {
      errorCallback('No response!');
      return;
    }
    renderStatus("saved URL: " + response.post_url);
    callback(response);
  };
  x.onerror = function() {
    errorCallback('Network error.');
  };
  var data = {}
  data.url = url;
  x.send(JSON.stringify(data));
}

function renderStatus(statusText) {
  document.getElementById('status').textContent = statusText;
}

document.addEventListener('DOMContentLoaded' , function() {
    var form = document.getElementById("urlpost");
    form.addEventListener("submit", processForm);
});

function processForm(e) {
    if (e.preventDefault) e.preventDefault();
    getCurrentTabUrl(function(url,title) {
        console.log(title);
        saveArticle(url, function(response) {
        }, function(errorMessage) {
        renderStatus('Error ' + errorMessage);
        });
    });
}