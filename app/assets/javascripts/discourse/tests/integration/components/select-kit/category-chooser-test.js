import createStore from "discourse/tests/helpers/create-store";
import I18n from "I18n";
import { discourseModule } from "discourse/tests/helpers/qunit-helpers";
import componentTest, {
  setupRenderingTest,
} from "discourse/tests/helpers/component-test";
import selectKit from "discourse/tests/helpers/select-kit-helper";

function template(options = []) {
  return `
    {{category-chooser
      value=value
      options=(hash
        ${options.join("\n")}
      )
    }}
  `;
}

discourseModule(
  "Integration | Component | select-kit/category-chooser",
  function (hooks) {
    setupRenderingTest(hooks);

    hooks.beforeEach(function () {
      this.set("subject", selectKit());
    });

    componentTest("with value", {
      template: template(),

      beforeEach() {
        this.set("value", 2);
      },

      async test(assert) {
        assert.equal(this.subject.header().value(), 2);
        assert.equal(this.subject.header().label(), "feature");
      },
    });

    componentTest("with excludeCategoryId", {
      template: template(["excludeCategoryId=2"]),
      async test(assert) {
        await this.subject.expand();

        assert.notOk(this.subject.rowByValue(2).exists());
      },
    });

    componentTest("with scopedCategoryId", {
      template: template(["scopedCategoryId=2"]),

      async test(assert) {
        await this.subject.expand();

        assert.equal(
          this.subject.rowByIndex(0).title(),
          "Discussion about features or potential features of Discourse: how they work, why they work, etc."
        );
        assert.equal(this.subject.rowByIndex(0).value(), 2);
        assert.equal(
          this.subject.rowByIndex(1).title(),
          "My idea here is to have mini specs for features we would like built but have no bandwidth to build"
        );
        assert.equal(this.subject.rowByIndex(1).value(), 26);
        assert.equal(
          this.subject.rows().length,
          2,
          "default content is scoped"
        );

        await this.subject.fillInFilter("bug");

        assert.equal(
          this.subject.rowByIndex(0).name(),
          "bug",
          "search finds outside of scope"
        );
      },
    });

    componentTest("with allowUncategorized=null", {
      template: template(["allowUncategorized=null"]),

      beforeEach() {
        this.siteSettings.allow_uncategorized_topics = false;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "category???");
      },
    });

    componentTest("with allowUncategorized=null rootNone=true", {
      template: template(["allowUncategorized=null", "none=true"]),

      beforeEach() {
        this.siteSettings.allow_uncategorized_topics = false;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "(no category)");
      },
    });

    componentTest("with disallowed uncategorized, none", {
      template: template(["allowUncategorized=null", "none='test.root'"]),

      beforeEach() {
        I18n.translations[I18n.locale].js.test = { root: "root none label" };
        this.siteSettings.allow_uncategorized_topics = false;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "root none label");
      },
    });

    componentTest("with allowed uncategorized", {
      template: template(["allowUncategorized=true"]),

      beforeEach() {
        this.siteSettings.allow_uncategorized_topics = true;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "uncategorized");
      },
    });

    componentTest("with allowed uncategorized and none=true", {
      template: template(["allowUncategorized=true", "none=true"]),

      beforeEach() {
        this.siteSettings.allow_uncategorized_topics = true;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "(no category)");
      },
    });

    componentTest("with allowed uncategorized and none", {
      template: template(["allowUncategorized=true", "none='test.root'"]),

      beforeEach() {
        I18n.translations[I18n.locale].js.test = { root: "root none label" };
        this.siteSettings.allow_uncategorized_topics = true;
      },

      test(assert) {
        assert.equal(this.subject.header().value(), null);
        assert.equal(this.subject.header().label(), "root none label");
      },
    });

    componentTest("filter is case insensitive", {
      template: template(),

      async test(assert) {
        await this.subject.expand();
        await this.subject.fillInFilter("bug");

        assert.ok(this.subject.rows().length, 1);
        assert.equal(this.subject.rowByIndex(0).name(), "bug");

        await this.subject.emptyFilter();
        await this.subject.fillInFilter("Bug");

        assert.ok(this.subject.rows().length, 1);
        assert.equal(this.subject.rowByIndex(0).name(), "bug");
      },
    });

    componentTest("filter works with non english characters", {
      template: `
      {{category-chooser
        value=value
      }}
    `,

      beforeEach() {
        const store = createStore();
        store.createRecord("category", {
          id: 1,
          name: "ch??? Qu???c ng???",
        });
      },

      async test(assert) {
        await this.subject.expand();
        await this.subject.fillInFilter("h???");

        assert.ok(this.subject.rows().length, 1);
        assert.equal(this.subject.rowByIndex(0).name(), "ch??? Qu???c ng???");
      },
    });

    componentTest("decodes entities in row title", {
      template: `
      {{category-chooser
        value=value
        options=(hash scopedCategoryId=1)
      }}
    `,

      beforeEach() {
        const store = createStore();
        store.createRecord("category", {
          id: 1,
          name: "cat-with-entities",
          description: "baz &quot;bar ???foo???",
        });
      },

      async test(assert) {
        await this.subject.expand();

        assert.equal(
          this.subject.rowByIndex(0).el()[0].title,
          'baz "bar ???foo???'
        );
      },
    });
  }
);
