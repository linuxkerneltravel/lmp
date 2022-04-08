<template>
  <div class="code-box">
    <highlightjs :language="codeType" :code="codeContent" />
  </div>
</template>

<script>
export default {
  name: 'CodeBox',
  props: {
    codeContent: {
      type: String,
      default: '',
    },
    codeType: {
      type: String,
      default: 'text',
    },
  },
};
</script>

<style scoped>
.code-box {
  text-align: left;
  height: 100%;
  width: 100%;
  border: 1;
}
</style>
