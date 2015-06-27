#!/bin/bash

SGX=$(dirname "$0")/../sgx
PYTHON=python

print_usage() {
  cat <<EOF
[usage] $0 [option]... [binary]
-a|--all  : test all cases
-h|--help : print help
-i|--instuct-test : run an instruction test
-ai|--all-instruction-tests : run all instruction test cases
--perf|--performance-measure : measure SGX emulator performance metrics 
[test]    : run a test case
EOF
  for f in test/*.c; do
    printf " %-30s: %s\n" "$f" "$(cat $f| head -1 | sed 's#//##g')"
  done
}

run_test() {
  mkdir -p log
  BASE=log/$(basename $1)
  $SGX $1 >$BASE.stdout 2>$BASE.stderr
  EXIT=$?
  EXPECT=0

  if [[ $1 =~ fault.* ]]; then
    EXPECT=139
  fi

  if [[ $1 =~ exception-div-zero.* ]]; then
    EXPECT=136
  fi

  if [[ $EXIT == $EXPECT ]]; then
    echo -n "$(tput setaf 2)OK$(tput sgr0)"
  else
    echo -n "$(tput setaf 1)FAIL ($EXIT)$(tput sgr0)"
  fi
}

perf_test() {
  mkdir -p log
  BASE=log/$(basename $1)
  $SGX $1 >$BASE.stdout 2>$BASE.stderr
  echo "$1"
  echo "-----------------------"
  awk '/count/ {print}' $BASE.stdout 
  awk '/region/ {print}' $BASE.stdout 
}

run_instruct_test() {
  mkdir -p log
  BASE=log/$(basename $1)
  $SGX $1 > $BASE.log 2>&1
  $PYTHON $1.py $(basename $1) > /dev/null 2>&1
  EXIT=$?
  EXPECT=0

  if [[ $EXIT == $EXPECT ]]; then
    echo -n "$(tput setaf 2)OK$(tput sgr0)"
  else
    echo -n "$(tput setaf 1)FAIL ($EXIT)$(tput sgr0)"
  fi
}

if [[ $# == 0 ]]; then
  print_usage
  exit 0
fi

case "$1" in
  -h|--help)
    print_usage
    exit 0
    ;;
  -a|--all)
    for f in test/*.c; do
      OUT=${f%%.c}
      if [[ "$OUT" == "test/simple-recv" ]]; then
      printf "%-30s: please test it with simple_send together\n" "$OUT" 
      continue  
      fi 
      if [[ "$OUT" == "test/simple-attest" ]]; then
      printf "%-30s: please test it with attest_nonEnc together\n" "$OUT" 
      continue  
      fi 
      if [[ "$OUT" == "test/simple-network" ]]; then
      printf "%-30s: please test it with attest_network together\n" "$OUT" 
      continue  
      fi 
      if [[ "$OUT" == "test/simple-quote" ]]; then
      printf "%-30s: please test it with simple_send together\n" "$OUT" 
      continue  
      fi 
      printf "%-30s: %s\n" "$OUT" "$(run_test $OUT)"
    done
    ;;
  -i|--instruct-test)
    if [[ $# -lt 2 ]]; then
      for f in test/test_kern/*.c; do
        printf " %-30s: %s\n" "$f" 
      done
      exit 0
    fi
    OUT=test/test_kern/$2
    make $OUT
    printf "%-30s: %s\n" "$OUT" "$(run_instruct_test $OUT)"
    ;;
  -ai|--all-instruction-tests)
    for f in test/test_kern/*.c; do
      OUT=${f%%.c}
      printf "%-30s: %s\n" "$OUT" "$(run_instruct_test $OUT)"
    done
    ;;
  --perf|--performance-measure)
    MATCH=0
    for f in test/*.c; do
      TARGET=${f%%.c}
      if [[ "test/$2" == "$TARGET" ]]; then
         perf_test $TARGET
         MATCH=1 
      elif [[ "$2" == "$TARGET" ]]; then
         perf_test $TARGET
         MATCH=1
      fi
    done
    if [ $MATCH -lt 1 ]; then
      echo "Usage: ./test.sh --perf app_name in test folder"
      echo "Ex) ./test.sh --perf simple"
    fi
    ;;
  *)
    make $1
    $SGX $1
    ;;
esac
