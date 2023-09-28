<template>
   <div>
      <label for="" v-if="props.label" class="block pl-3 ml-px text-sm font-medium text-gray-700">{{
         props.label
      }}</label>
      <div class="mt-1">
         <input type="text" :value="props.value" />
      </div>
   </div>
</template>

<script setup>
const props = defineProps({
   value: {
      type: String,
      required: true,
   },
   label: {
      type: String,
      default: null,
   },
});
</script>
