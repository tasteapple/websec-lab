// file: app/static/js/app.js

(function () {
  /*
   * 공통 UI 스크립트입니다.
   *
   * 현재는 힌트 박스와 사이드바 섹션 토글을 담당합니다.
   */

  function setupHintToggles() {
    const buttons = document.querySelectorAll("[data-toggle='hint']");

    buttons.forEach((button) => {
      button.addEventListener("click", () => {
        const box = button.closest(".hint-box");
        if (!box) {
          return;
        }

        const body = box.querySelector(".hint-box__body");
        if (!body) {
          return;
        }

        const isHidden = body.hasAttribute("hidden");

        if (isHidden) {
          body.removeAttribute("hidden");
          button.textContent = "힌트 닫기";
        } else {
          body.setAttribute("hidden", "");
          button.textContent = "힌트 열기";
        }
      });
    });
  }

  function setupSidebarToggles() {
    const buttons = document.querySelectorAll("[data-sidebar-toggle]");

    buttons.forEach((button) => {
      const sectionName = button.dataset.sidebarToggle;
      const body = document.querySelector(
        `[data-sidebar-section="${sectionName}"]`
      );

      if (!body) {
        return;
      }

      button.addEventListener("click", () => {
        const isHidden = body.hasAttribute("hidden");

        if (isHidden) {
          body.removeAttribute("hidden");
          button.setAttribute("aria-expanded", "true");
        } else {
          body.setAttribute("hidden", "");
          button.setAttribute("aria-expanded", "false");
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupHintToggles();
    setupSidebarToggles();
  });
})();