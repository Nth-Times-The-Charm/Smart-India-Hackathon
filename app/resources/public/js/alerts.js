function transitionHide() {
    var obj = this.event.target.parentElement;
    obj.style.opacity = 0;
    setTimeout(function () {
      obj.style.display = "none";
    }, 200);
  }