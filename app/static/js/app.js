// file: app/static/js/app.js

(function () {
  /*
   * 공통 UI 스크립트입니다.
   *
   * - 힌트 박스 열기/닫기
   * - 사이드바 섹션 열림/닫힘 상태 저장
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

  function setSidebarSectionState(button, body, isOpen) {
    if (isOpen) {
      body.removeAttribute("hidden");
      button.setAttribute("aria-expanded", "true");
    } else {
      body.setAttribute("hidden", "");
      button.setAttribute("aria-expanded", "false");
    }
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

      const storageKey = `websec-lab:sidebar:${sectionName}`;
      const savedState = window.localStorage.getItem(storageKey);

      /*
       * 저장된 상태가 있으면 서버 렌더링 기본값보다 사용자의 선택을 우선합니다.
       * 저장된 상태가 없으면 base.html에서 내려준 기본 open/closed 상태를 그대로 둡니다.
       */
      if (savedState === "open") {
        setSidebarSectionState(button, body, true);
      }

      if (savedState === "closed") {
        setSidebarSectionState(button, body, false);
      }

      button.addEventListener("click", () => {
        const isHidden = body.hasAttribute("hidden");
        const nextIsOpen = isHidden;

        setSidebarSectionState(button, body, nextIsOpen);

        window.localStorage.setItem(
          storageKey,
          nextIsOpen ? "open" : "closed"
        );
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupHintToggles();
    setupSidebarToggles();
  });
})();